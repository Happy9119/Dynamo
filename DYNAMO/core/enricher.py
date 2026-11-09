import time
from typing import Callable, Optional

from core.ai_engine import generate_asset_intelligence
from storage.db_storage import (
    list_pending_ai, load_asset_for_ai, save_ai_analysis,
)


RETRYABLE_STATUSES = {"invalid_json", "schema_error", "http_error",
                      "unavailable", "error", "timeout"}


def enrich_assets(
    asset_ids: list[int],
    progress_callback: Optional[Callable[[str], None]] = None,
    risk_min: int = 20,
    scan_id: Optional[int] = None,
) -> dict:
    def report(msg: str) -> None:
        if progress_callback:
            progress_callback(msg)
        else:
            print(msg)

    try:
        from storage.db_storage import prune_ai_cache
        pruned = prune_ai_cache(max_age_days=30)
        if pruned:
            report(f"  [i] pruned {pruned} stale AI cache rows")
    except Exception:
        pass

    total = len(asset_ids)
    enriched = 0
    skipped = 0
    failed = 0
    timed_out = 0
    retried = 0
    started = time.perf_counter()

    for i, aid in enumerate(asset_ids, 1):
        try:
            asset = load_asset_for_ai(aid)
        except Exception as e:
            failed += 1
            report(f"  [!] {i}/{total}  asset_id={aid} — load failed: {e}")
            continue

        if not asset:
            failed += 1
            report(f"  [!] {i}/{total}  asset_id={aid} — not found")
            continue

        if asset.risk_score < risk_min:
            skipped += 1
            continue

        report(f"  [{i}/{total}] AI → {asset.asset_value} (risk={asset.risk_score})")
        t0 = time.perf_counter()

        result = None
        last_err = None
        did_retry = False

        for attempt in (1, 2):
            result = generate_asset_intelligence(asset)

            if result and result.intelligence:
                break

            if result and result.status == "timeout":
                last_err = f"timeout after {REQUEST_TIMEOUT_SHOWN()}s"
            elif result and result.error:
                last_err = result.error
            elif not last_err:
                last_err = "no intelligence in response"

            status = result.status if result else "exception"

            retry_this = (
                status in RETRYABLE_STATUSES
                and not (status == "timeout" and REQUEST_TIMEOUT_SHOWN() >= 900)
            )

            if attempt == 1 and retry_this:
                did_retry = True
                short = (last_err or "unknown")[:80]
                report(f"      [~] attempt 1 {status} ({short}), retrying")
                continue

            if attempt == 1:
                short = (last_err or "unknown")[:80]
                report(f"      [~] attempt 1 {status} ({short}), no retry")
                break

        if did_retry:
            retried += 1

        dur = time.perf_counter() - t0

        if result and result.intelligence:
            save_ai_analysis(aid, result.intelligence.model_dump_json(), scan_id=scan_id)
            enriched += 1
            report(f"      [✓] enriched in {dur:.0f}s")
        elif result and result.status == "timeout":
            timed_out += 1
            report(f"      [!] timeout after {dur:.0f}s")
        else:
            failed += 1
            report(f"      [!] {last_err} (after {dur:.0f}s)")

    elapsed = int(time.perf_counter() - started)
    return {
        "total": total,
        "enriched": enriched,
        "skipped": skipped,
        "failed": failed,
        "timed_out": timed_out,
        "retried": retried,
        "elapsed_sec": elapsed,
    }


def REQUEST_TIMEOUT_SHOWN() -> int:
    import os
    return int(os.environ.get("OLLAMA_TIMEOUT", "900"))


def enrich_scan(scan_id: int,
                progress_callback: Optional[Callable[[str], None]] = None,
                risk_min: int = 20) -> dict:
    ids = list_pending_ai(scan_id=scan_id, risk_min=risk_min)
    return enrich_assets(ids, progress_callback=progress_callback,
                         risk_min=risk_min, scan_id=scan_id)


def enrich_domain(domain_id: int,
                  progress_callback: Optional[Callable[[str], None]] = None,
                  risk_min: int = 20) -> dict:
    ids = list_pending_ai(domain_id=domain_id, risk_min=risk_min)
    return enrich_assets(ids, progress_callback=progress_callback, risk_min=risk_min)


def enrich_all(progress_callback: Optional[Callable[[str], None]] = None,
               risk_min: int = 20,
               limit: Optional[int] = None) -> dict:
    ids = list_pending_ai(risk_min=risk_min)
    if limit:
        ids = ids[:limit]
    return enrich_assets(ids, progress_callback=progress_callback, risk_min=risk_min)