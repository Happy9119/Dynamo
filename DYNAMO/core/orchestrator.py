import asyncio
import os
import re
import json
import shutil
import threading
from datetime import datetime
from urllib.parse import urlparse, urljoin as _urljoin

from storage.models import _utcnow
from modules.subfinder_runner import run_subfinder
from modules.httpx_runner import run_httpx, check_urls_live
from modules.nmap_runner import run_nmap
from modules.crt_runner import run_crt
from modules.gau_runner import run_gau
from modules.wayback_runner import run_wayback
from modules.katana_runner import run_katana
from modules.nuclei_runner import run_nuclei
from modules.ffuf_runner import run_ffuf
from modules.sqlmap_runner import run_sqlmap
from core.normalizer import normalize_httpx
from core.nmap_parser import parse_nmap_xml
from core.nmap_normalizer import normalize_nmap
from core.correlator import correlate_assets
from core.risk_engine import calculate_risk
from core.domain_utils import extract_apex, host_belongs_to_apex
from core.artifact_writer import ArtifactWriter
from schemas.asset import NucleiFinding, SQLiFinding, VulnFinding, Asset
from storage.db_storage import (
    save_asset_to_db,
    create_scan,
    deactivate_missing_assets,
    update_scan_status,
    get_active_asset_count,
)
from storage.database import SessionLocal
from storage.models import (
    ScanProgressModel, PhaseResultModel,
    AssetVulnModel, NucleiFindingModel, SQLiFindingModel,
)
from vapt.runner import (
    run_js_analysis, select_js_urls,
    run_passive_checks, run_file_probes, run_param_probes,
)
from config.tools import (
    NMAP_CONCURRENCY,
    AI_RISK_THRESHOLD,
    HTTPX_BULK_TIMEOUT,
    NUCLEI_BIN,
)

try:
    import resource
    _soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(8192, _hard), _hard))
except Exception:
    pass

STATIC_EXT = re.compile(
    r"\.(js|css|png|jpe?g|gif|ico|svg|woff2?|ttf|eot|pdf|"
    r"docx?|xlsx?|zip|tar|gz|mp4|webm|map)$",
    re.I,
)


def _host_of(url):
    if not url:
        return ""
    if "//" not in url:
        url = "http://" + url
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _ensure_schema(report):
    try:
        from sqlalchemy import inspect as _sql_inspect
        from storage.database import engine as _engine
        from storage.models import Base as _Base

        _insp = _sql_inspect(_engine)
        _existing = set(_insp.get_table_names())
        for _tname, _table in _Base.metadata.tables.items():
            if _tname not in _existing:
                continue
            _db_cols = {c["name"] for c in _insp.get_columns(_tname)}
            for _col in _table.columns:
                if _col.name not in _db_cols:
                    report(
                        f"[*] Schema drift detected: {_tname}.{_col.name} missing "
                        f"— running migration"
                    )
                    from update_db import upgrade_database_schema
                    upgrade_database_schema()
                    return
    except Exception as e:
        report(f"[!] Schema sync failed: {e}")
        raise


def _load_phase_for_scan(scan_id, phase_name):
    session = SessionLocal()
    try:
        res = session.query(PhaseResultModel).filter_by(
            scan_id=scan_id, phase_name=phase_name).first()
        return json.loads(res.result_json) if res else None
    finally:
        session.close()


def _is_interesting_param_url(u, apex):
    if not u.startswith("http"):
        return False
    path_part, sep, query_part = u.partition("?")
    if not sep or "=" not in query_part:
        return False
    host = _host_of(u)
    if not host_belongs_to_apex(host, apex):
        return False
    if STATIC_EXT.search(path_part):
        return False
    return True


def _normalize_params(u):
    base, _, query = u.partition("?")
    if not query:
        return u
    seen = set()
    parts = []
    for kv in query.split("&"):
        k, _, _v = kv.partition("=")
        if k and k not in seen:
            seen.add(k)
            parts.append(f"{k}=123")
    return f"{base}?{'&'.join(parts)}"


def _build_host_index(assets):
    by_host = {}
    for a in assets:
        key = _host_of(a.url or "") or (a.asset_value or "").lower()
        if key:
            by_host.setdefault(key, a)
        for ip in (a.resolved_ips or []):
            if ip:
                by_host.setdefault(ip.lower(), a)
    return by_host


def _dedupe_seq(seq):
    seen, out = set(), []
    for u in seq or []:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def _attach_url_intel(assets, historical, crawled, discovered_paths, nuclei, sqli,
                      live_archive_urls=None, js_endpoints=None, logger=None,
                      apex=None):
    log = logger or print
    by_host = _build_host_index(assets)
    skipped_out_of_scope = 0

    def bucket(url):
        nonlocal skipped_out_of_scope
        if not url:
            return None
        h = _host_of(url)
        if not h:
            return None
        a = by_host.get(h)
        if a is None:
            if apex and not host_belongs_to_apex(h, apex):
                skipped_out_of_scope += 1
                return None
            a = Asset(
                asset_value=h,
                resolved_ips=[],
                url=url,
                technologies=[],
                services=[],
            )
            assets.append(a)
            by_host[h] = a
        return a

    def _safe_append(asset, attr, value):
        if not hasattr(asset, attr):
            return
        lst = getattr(asset, attr)
        if value not in lst:
            lst.append(value)

    for url in _dedupe_seq(historical):
        a = bucket(url)
        if a:
            _safe_append(a, "historical_urls", url)

    for url in _dedupe_seq(live_archive_urls or []):
        a = bucket(url)
        if a:
            _safe_append(a, "live_urls", url)

    for url in _dedupe_seq(crawled or []):
        a = bucket(url)
        if a:
            _safe_append(a, "crawled_urls", url)

    for url in _dedupe_seq(discovered_paths or []):
        a = bucket(url)
        if a:
            _safe_append(a, "discovered_paths", url)

    for url in _dedupe_seq(js_endpoints or []):
        a = bucket(url)
        if a:
            _safe_append(a, "js_endpoints", url)

    from core.cve_lookup import lookup_from_nuclei

    nuclei_attached = 0
    nuclei_dropped = 0
    for f in nuclei or []:
        if not isinstance(f, dict):
            nuclei_dropped += 1
            continue

        host = (f.get("host") or "").lower()
        matched_at = (f.get("matched-at") or f.get("matched_at") or "").strip()

        a = by_host.get(host) if host else None
        if a is None and matched_at:
            a = bucket(matched_at)
        if a is None and matched_at:
            parsed_host = _host_of(matched_at)
            if parsed_host:
                a = bucket(f"http://{parsed_host}")

        if a is None:
            nuclei_dropped += 1
            log(f"    [!] nuclei finding could not be mapped "
                f"(template={f.get('template-id', '?')}, host={host or matched_at or '?'})")
            continue

        info = f.get("info", {}) or {}
        finding = NucleiFinding(
            template_id=f.get("template-id"),
            name=info.get("name"),
            severity=info.get("severity"),
            matched_at=f.get("matched-at"),
            host=host,
            description=info.get("description"),
            reference=info.get("reference") or [],
            raw=f,
        )
        a.nuclei_findings.append(finding)
        nuclei_attached += 1

        existing_ids = {c.get("cve") for c in a.cves if c.get("cve")}
        for cve in lookup_from_nuclei([finding]):
            if cve.get("cve") and cve["cve"] not in existing_ids:
                a.cves.append(cve)
                existing_ids.add(cve["cve"])

    sqli_attached = 0
    sqli_dropped = 0
    for s in sqli or []:
        if not isinstance(s, dict) or not s.get("vulnerable"):
            continue
        sqli_url = (s.get("url") or "").strip()
        if not sqli_url:
            sqli_dropped += 1
            continue
        a = bucket(sqli_url)
        if a is None:
            sqli_dropped += 1
            log(f"    [!] SQLi finding could not be mapped: {sqli_url}")
            continue
        a.sqli_findings.append(SQLiFinding(
            url=sqli_url,
            vulnerable=True,
            technique=s.get("technique"),
            payload=s.get("payload"),
        ))
        sqli_attached += 1

    for a in assets:
        params = set()
        for url in (a.crawled_urls + a.historical_urls):
            if "?" in url and "=" in url:
                params.add(url)
        a.parameter_urls = sorted(params)

    if skipped_out_of_scope:
        log(f"    [!] attach: skipped {skipped_out_of_scope} out-of-scope URL(s) "
            f"(raw data preserved in katana_output.txt)")
    if nuclei_dropped or sqli_dropped:
        log(f"    [!] attach summary — nuclei {nuclei_attached} attached / "
            f"{nuclei_dropped} dropped, sqli {sqli_attached} attached / "
            f"{sqli_dropped} dropped")


def _attach_vapt_findings(assets, raw_findings, logger=None, apex=None):
    log = logger or print
    by_host = _build_host_index(assets)
    attached = 0
    dropped = 0
    skipped_out_of_scope = 0
    for f in raw_findings or []:
        if not isinstance(f, dict):
            dropped += 1
            continue

        url = (f.get("url") or "").strip()
        host = _host_of(url)
        if not host:
            dropped += 1
            log(f"    [!] VAPT finding dropped (bad url): "
                f"type={f.get('vuln_type', '?')} url={url!r}")
            continue

        owner = by_host.get(host)
        if owner is None:
            if apex and not host_belongs_to_apex(host, apex):
                skipped_out_of_scope += 1
                continue
            owner = Asset(
                asset_value=host,
                resolved_ips=[],
                url=url,
                technologies=[],
                services=[],
            )
            assets.append(owner)
            by_host[host] = owner

        try:
            owner.vulns.append(VulnFinding(
                vuln_type=f.get("vuln_type", "unknown"),
                severity=f.get("severity", "info"),
                url=url,
                parameter=f.get("parameter"),
                evidence=f.get("evidence"),
                remediation=f.get("remediation"),
            ))
            attached += 1
        except Exception as e:
            dropped += 1
            log(f"    [!] VAPT finding build failed: {e}")

    if skipped_out_of_scope:
        log(f"    [!] VAPT attach: skipped {skipped_out_of_scope} out-of-scope finding(s)")
    if dropped:
        log(f"    [!] VAPT attach summary — {attached} attached / {dropped} dropped")


def _dedupe_correlated(correlated):
    out = {}
    order = []
    for a in correlated:
        key = (a.asset_value or "").lower().strip()
        if not key:
            continue
        if key in out:
            existing = out[key]
            for attr in (
                "historical_urls", "live_urls", "crawled_urls",
                "parameter_urls", "discovered_paths", "js_endpoints",
            ):
                lst = getattr(existing, attr, [])
                for v in getattr(a, attr, []) or []:
                    if v not in lst:
                        lst.append(v)
                setattr(existing, attr, lst)
            for finding in a.nuclei_findings or []:
                existing.nuclei_findings.append(finding)
            for s in a.sqli_findings or []:
                existing.sqli_findings.append(s)
            for v in a.vulns or []:
                existing.vulns.append(v)
            for cve in a.cves or []:
                cve_id = cve.get("cve") if isinstance(cve, dict) else None
                if cve_id and not any(
                    c.get("cve") == cve_id for c in existing.cves if isinstance(c, dict)
                ):
                    existing.cves.append(cve)
            existing_keys = {(s.port, s.protocol) for s in existing.services}
            for svc in a.services or []:
                if (svc.port, svc.protocol) not in existing_keys:
                    existing.services.append(svc)
                    existing_keys.add((svc.port, svc.protocol))
            for tech in a.technologies or []:
                if tech not in existing.technologies:
                    existing.technologies.append(tech)
            for ip in a.resolved_ips or []:
                if ip not in existing.resolved_ips:
                    existing.resolved_ips.append(ip)
        else:
            out[key] = a
            order.append(key)
    return [out[k] for k in order]


def _verify_scan_save(scan_id, correlated, mode, report, tool_status):
    if mode != "full":
        return None

    nuclei_clean = tool_status.get("nuclei") in ("OK", "EMPTY")
    vapt_clean = tool_status.get("vapt") in ("OK", "EMPTY")
    sqlmap_clean = tool_status.get("sqlmap") in ("OK", "EMPTY")

    session = SessionLocal()
    try:
        from storage.models import ScanAssetModel
        asset_ids = [
            row[0] for row in
            session.query(ScanAssetModel.asset_id)
            .filter(ScanAssetModel.scan_id == scan_id).all()
        ]
        if not asset_ids:
            return "no scan_assets rows"

        issues = []
        if vapt_clean:
            actual = session.query(AssetVulnModel).filter(
                AssetVulnModel.asset_id.in_(asset_ids)).count()
            expected = sum(len(a.vulns) for a in correlated)
            if actual < expected:
                issues.append(f"VAPT {actual}/{expected}")
        if nuclei_clean:
            actual = session.query(NucleiFindingModel).filter(
                NucleiFindingModel.asset_id.in_(asset_ids)).count()
            expected = sum(len(a.nuclei_findings) for a in correlated)
            if actual < expected:
                issues.append(f"Nuclei {actual}/{expected}")
        if sqlmap_clean:
            actual = session.query(SQLiFindingModel).filter(
                SQLiFindingModel.asset_id.in_(asset_ids)).count()
            expected = sum(len(a.sqli_findings) for a in correlated)
            if actual < expected:
                issues.append(f"SQLi {actual}/{expected}")

        if issues:
            msg = "DB verification shortfall: " + ", ".join(issues)
            report(f"    [!] {msg}")
            return msg
        return None
    except Exception as e:
        report(f"    [!] DB verification failed: {e}")
        return None
    finally:
        session.close()


def reconcile_scan(scan_id):
    from storage.models import ScanModel

    session = SessionLocal()
    try:
        scan = session.query(ScanModel).get(scan_id)
        if not scan:
            return {"ok": False, "error": f"scan {scan_id} not found"}
        target = scan.target
        mode = scan.mode or "full"
    finally:
        session.close()

    apex = extract_apex(target) or target.lower()

    httpx_results = _load_phase_for_scan(scan_id, "httpx")
    if not httpx_results:
        return {"ok": False, "error": "no httpx phase result cached"}

    nmap_results = _load_phase_for_scan(scan_id, "nmap") or []
    live_archive_urls = _load_phase_for_scan(scan_id, "live_archive") or []
    crawled = _load_phase_for_scan(scan_id, "katana") or []
    discovered = _load_phase_for_scan(scan_id, "ffuf") or []

    nuclei_phase = _load_phase_for_scan(scan_id, "nuclei") or {}
    if isinstance(nuclei_phase, dict):
        nuclei = nuclei_phase.get("all", (nuclei_phase.get("urls") or []) + (nuclei_phase.get("ips") or []))
    elif isinstance(nuclei_phase, list):
        nuclei = nuclei_phase
    else:
        nuclei = []

    vapt_passive = _load_phase_for_scan(scan_id, "vapt_passive") or []
    vapt_active = _load_phase_for_scan(scan_id, "vapt_active") or []
    js_phase = _load_phase_for_scan(scan_id, "js_analysis") or {}
    js_findings = js_phase.get("findings") or [] if isinstance(js_phase, dict) else []
    js_endpoints = js_phase.get("endpoints") or [] if isinstance(js_phase, dict) else []
    sqli = _load_phase_for_scan(scan_id, "sqlmap") or []

    passive_phase = _load_phase_for_scan(scan_id, "passive_discovery") or {}
    gau_urls = passive_phase.get("gau_urls") or []
    wb_urls = passive_phase.get("wb_urls") or []

    httpx_assets = [normalize_httpx(r) for r in httpx_results]
    nmap_assets = normalize_nmap(nmap_results)
    correlated = correlate_assets(httpx_assets, nmap_assets)

    _attach_url_intel(
        correlated,
        historical=(gau_urls + wb_urls),
        crawled=crawled,
        discovered_paths=discovered,
        nuclei=nuclei,
        sqli=sqli,
        live_archive_urls=live_archive_urls,
        js_endpoints=js_endpoints,
        logger=print,
        apex=apex,
    )
    vapt_all = vapt_passive + vapt_active + js_findings
    if vapt_all:
        _attach_vapt_findings(correlated, vapt_all, logger=print, apex=apex)

    correlated = _dedupe_correlated(correlated)
    for a in correlated:
        a.risk_score, a.risk_summary = calculate_risk(a)

    tool_status = {
        "nuclei": "OK" if nuclei else "EMPTY",
        "vapt": "OK" if vapt_all else "EMPTY",
        "sqlmap": "OK" if sqli else "EMPTY",
    }

    saved = 0
    failures = []
    for a in correlated:
        if not a.asset_value or not a.asset_value.strip():
            continue
        try:
            save_asset_to_db(a, scan_id, mode=mode, tool_status=tool_status)
            saved += 1
        except Exception as e:
            failures.append({"asset": a.asset_value, "error": str(e)[:200]})

    update_scan_status(
        scan_id, "partial" if failures else "completed",
        completed_at=datetime.now(),
        correlated_asset_count=len(correlated),
        saved_asset_count=saved,
        error_message=f"reconcile: {len(failures)} failed" if failures else None,
    )

    return {
        "ok": True,
        "reconcile_target": target,
        "total": len(correlated),
        "saved": saved,
        "failures": failures,
    }


async def run_pipeline(domain, progress_callback=None, mode="quick",
                       enrich_ai=False, wait_for_enrichment=False,
                       fresh=False):
    if mode not in ("quick", "full"):
        raise ValueError(f"invalid mode: {mode}")

    apex = extract_apex(domain) or domain.lower()
    sqlmap_batch_size = int(os.environ.get("SQLMAP_BATCH_SIZE", "4"))
    ffuf_batch_size = int(os.environ.get("FFUF_BATCH_SIZE", "10"))

    def report(msg):
        print(msg)
        if progress_callback:
            progress_callback(msg)

    report(f"\n[+] Starting DYNAMO scan: {domain} (mode={mode})\n")

    from storage.database import SessionLocal
    from storage.models import ScanModel
    session = SessionLocal()
    try:
        if fresh:
            scan_id = create_scan(domain, mode=mode)
            report(f"[*] Forced fresh scan #{scan_id} (--fresh)")
        else:
            existing = session.query(ScanModel).filter(
                ScanModel.target == domain,
                ScanModel.mode == mode,
                ScanModel.status == "running",
            ).order_by(ScanModel.started_at.desc()).first()

            if existing:
                scan_id = existing.id
                report(f"[*] Resuming interrupted scan #{scan_id} "
                       f"(use --fresh to force a new scan instead)")
                update_scan_status(scan_id, "running")
            else:
                scan_id = create_scan(domain, mode=mode)
    finally:
        session.close()

    try:
        _ensure_schema(report)
    except Exception as e:
        report(f"\n[!] Aborting — schema sync failed: {e}\n")
        update_scan_status(scan_id, "failed",
                           completed_at=datetime.now(),
                           error_message=f"schema sync failed: {e}"[:2000])
        raise

    writer = ArtifactWriter(apex, scan_id)
    tool_status = {}

    def report_progress(phase, status, count=0):
        report(f"[*] Phase {phase} — {status} ({count} items)")
        session = SessionLocal()
        try:
            prog = session.query(ScanProgressModel).filter_by(
                scan_id=scan_id, phase=phase).first()
            if not prog:
                prog = ScanProgressModel(scan_id=scan_id, phase=phase)
                session.add(prog)
            prog.status = status
            prog.count = count
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    def save_phase(phase_name, data):
        session = SessionLocal()
        try:
            session.query(PhaseResultModel).filter_by(
                scan_id=scan_id, phase_name=phase_name).delete()
            session.add(PhaseResultModel(
                scan_id=scan_id, phase_name=phase_name,
                result_json=json.dumps(data),
            ))
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    def load_phase(phase_name):
        return _load_phase_for_scan(scan_id, phase_name)

    try:
        cached_p1 = load_phase("passive_discovery")
        if cached_p1:
            all_subs = cached_p1["all_subs"]
            subdomains = cached_p1["subdomains"]
            crt_subs = cached_p1["crt_subs"]
            gau_urls = cached_p1["gau_urls"]
            wb_urls = cached_p1["wb_urls"]
            tool_status.update(cached_p1.get("statuses", {}))
            report_progress("1-Passive", "Resumed from cache", len(all_subs))
        else:
            report_progress("1-Passive", "running")
            phase1 = await asyncio.gather(
                run_subfinder(domain, progress=report),
                run_crt(domain, progress=report),
                run_gau(domain, progress=report),
                run_wayback(domain, progress=report),
                return_exceptions=True,
            )
            phase1_names = ["subfinder", "crt", "gau", "wayback"]
            phase1_out = []
            for name, result in zip(phase1_names, phase1):
                if isinstance(result, Exception):
                    report(f"    [!] {name} failed: {str(result)[:200]}")
                    phase1_out.append([])
                    tool_status[name] = "FAILED"
                elif isinstance(result, list):
                    phase1_out.append(result)
                    tool_status[name] = "OK" if result else "EMPTY"
                else:
                    phase1_out.append([])
                    tool_status[name] = "FAILED"

            subdomains, crt_subs, gau_urls, wb_urls = phase1_out
            all_subs = sorted({s.lower() for s in (subdomains + crt_subs + [domain]) if s})

            save_phase("passive_discovery", {
                "all_subs": all_subs, "subdomains": subdomains,
                "crt_subs": crt_subs, "gau_urls": gau_urls, "wb_urls": wb_urls,
                "statuses": {k: tool_status[k] for k in phase1_names if k in tool_status},
            })
            report_progress("1-Passive", "completed", len(all_subs))

        writer.write_subfinder(subdomains)
        writer.write_crt(crt_subs)
        writer.write_gau(gau_urls)
        writer.write_wayback(wb_urls)
        writer.write_unique_subdomains(all_subs)

        if not subdomains and not crt_subs:
            report("[!] subfinder and crt returned 0 subdomains — aborting")
            update_scan_status(
                scan_id, "failed", completed_at=datetime.now(),
                error_message="no subdomains discovered",
                tool_status_json=json.dumps(tool_status),
            )
            raise ValueError("no subdomains discovered")

        update_scan_status(
            scan_id, "running",
            subfinder_count=len(subdomains), crt_count=len(crt_subs),
            gau_count=len(gau_urls), wayback_count=len(wb_urls),
            httpx_count=0,
        )

        cached_p2 = load_phase("httpx")
        if cached_p2:
            httpx_results = cached_p2
            report_progress("2-Httpx", "Resumed from cache", len(httpx_results))
        else:
            report_progress("2-Httpx", "running")
            httpx_results = await run_httpx(all_subs)
            save_phase("httpx", httpx_results)
            report_progress("2-Httpx", "completed", len(httpx_results))

        update_scan_status(scan_id, "running", httpx_count=len(httpx_results))
        httpx_assets = [normalize_httpx(r) for r in httpx_results]
        unique_ips = {ip for a in httpx_assets for ip in a.resolved_ips if ip}
        writer.write_httpx(httpx_results, httpx_assets)

        cached_p25 = load_phase("live_archive")
        if cached_p25:
            live_archive_urls = cached_p25
            report_progress("2.5-Archive", "Resumed from cache", len(live_archive_urls))
        else:
            report_progress("2.5-Archive", "running")
            archive_pool = sorted({
                u for u in (gau_urls + wb_urls)
                if u.startswith("http") and not STATIC_EXT.search(u.split("?", 1)[0])
                and host_belongs_to_apex(_host_of(u), apex)
            })
            live_archive = []
            if archive_pool:
                try:
                    live_archive = await check_urls_live(archive_pool, timeout=HTTPX_BULK_TIMEOUT)
                except Exception as e:
                    report(f"    [!] archive probe failed: {str(e)[:200]}")
            live_archive_urls = sorted(set(live_archive))
            save_phase("live_archive", live_archive_urls)
            report_progress("2.5-Archive", "completed", len(live_archive_urls))

        writer.write_live_archive_urls(live_archive_urls)
        writer.write_unique_archive_urls(live_archive_urls)

        nmap_dir = f"nmap_outputs/{apex}"

        cached_p3 = load_phase("nmap")
        if cached_p3:
            all_nmap = cached_p3
            report_progress("3-Nmap", "Resumed from cache", len(all_nmap))
        else:
            report_progress("3-Nmap", "running")

            async def scan_ip(ip):
                try:
                    xml = await run_nmap(ip, save_dir=nmap_dir, scan_id=scan_id)
                    return parse_nmap_xml(xml) if xml else []
                except Exception as e:
                    report(f"    [!] nmap failed on {ip}: {e}")
                    return []

            nmap_sem = asyncio.Semaphore(NMAP_CONCURRENCY)

            async def scan_ip_throttled(ip):
                async with nmap_sem:
                    return await scan_ip(ip)

            nmap_chunks = await asyncio.gather(
                *(scan_ip_throttled(ip) for ip in unique_ips))
            all_nmap = [row for chunk in nmap_chunks for row in chunk]
            save_phase("nmap", all_nmap)
            report_progress("3-Nmap", "completed", len(all_nmap))

        nmap_assets = normalize_nmap(all_nmap)
        update_scan_status(
            scan_id, "running",
            nmap_ip_count=len(unique_ips), nmap_service_count=len(all_nmap),
        )
        writer.write_nmap_merged(nmap_dir, unique_ips)

        live_hosts = [a.url for a in httpx_assets if a.url]

        crawled, discovered, nuclei, sqli = [], [], [], []
        vapt_findings = []
        js_endpoints = []
        resolved_endpoints = set()
        param_pool = []
        nuc_urls, nuc_ips = [], []

        if mode == "full":
            cached_p4 = load_phase("katana")
            if cached_p4:
                crawled = cached_p4
                report_progress("4-Katana", "Resumed from cache", len(crawled))
            else:
                report_progress("4-Katana", "running")
                try:
                    crawled = await run_katana(live_hosts, domain, progress=report)
                except Exception as e:
                    report(f"    [!] katana failed: {str(e)[:200]}")
                save_phase("katana", crawled)
                report_progress("4-Katana", "completed", len(crawled))
            update_scan_status(scan_id, "running", katana_count=len(crawled))
            writer.write_katana(crawled)
            tool_status["katana"] = "OK" if crawled else "EMPTY"

            cached_p5 = load_phase("ffuf")
            if cached_p5:
                discovered = cached_p5
                report_progress("5-FFUF", "Resumed from cache", len(discovered))
            else:
                report_progress("5-FFUF", "running")
                discovered_set = set()
                for i in range(0, len(live_hosts), ffuf_batch_size):
                    batch = live_hosts[i:i + ffuf_batch_size]
                    chunks = await asyncio.gather(
                        *(run_ffuf(h, progress=report) for h in batch),
                        return_exceptions=True,
                    )
                    for chunk in chunks:
                        if isinstance(chunk, list):
                            discovered_set.update(chunk)
                discovered = sorted(discovered_set)
                save_phase("ffuf", discovered)
                report_progress("5-FFUF", "completed", len(discovered))
            update_scan_status(scan_id, "running", ffuf_count=len(discovered))
            writer.write_ffuf(discovered)
            tool_status["ffuf"] = "OK" if discovered else "EMPTY"

            nuclei_available = bool(
                shutil.which(NUCLEI_BIN) or shutil.which(NUCLEI_BIN.split("/")[-1])
            )

            cached_p6 = load_phase("nuclei")
            if cached_p6:
                if isinstance(cached_p6, dict):
                    nuc_urls = cached_p6.get("urls", [])
                    nuc_ips = cached_p6.get("ips", [])
                    nuclei = cached_p6.get("all", nuc_urls + nuc_ips)
                    cached_errors = cached_p6.get("errors") or []
                    if cached_errors:
                        tool_status["nuclei"] = "FAILED"
                        for err in cached_errors:
                            report(f"    [!] cached nuclei error: {err}")
                    else:
                        tool_status["nuclei"] = "OK" if nuclei else "EMPTY"
                else:
                    nuclei = cached_p6
                    nuc_urls, nuc_ips = [], []
                    _ip_re = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
                    for f in nuclei:
                        h = (f.get("host") or f.get("matched-at") or "").lower()
                        if "//" in h:
                            ho = h.split("//", 1)[1].split("/", 1)[0].split(":", 1)[0]
                        else:
                            ho = h.split(":", 1)[0]
                        (nuc_ips if _ip_re.match(ho) else nuc_urls).append(f)
                    tool_status["nuclei"] = "OK" if nuclei else "EMPTY"
                report_progress("6-Nuclei", "Resumed from cache", len(nuclei))
            elif not nuclei_available:
                tool_status["nuclei"] = "SKIPPED"
                nuclei, nuc_urls, nuc_ips = [], [], []
                report_progress("6-Nuclei", "skipped (binary missing)", 0)
                report(f"    [!] nuclei not installed ({NUCLEI_BIN}) — skipping")
            else:
                report_progress("6-Nuclei", "running")
                nuc_url_res, nuc_ip_res = await asyncio.gather(
                    run_nuclei(live_hosts, progress=report),
                    run_nuclei(sorted(unique_ips), progress=report),
                    return_exceptions=True,
                )
                nuclei_errors = []
                if isinstance(nuc_url_res, Exception):
                    nuclei_errors.append(f"urls: {str(nuc_url_res)[:200]}")
                if isinstance(nuc_ip_res, Exception):
                    nuclei_errors.append(f"ips: {str(nuc_ip_res)[:200]}")
                nuc_urls = nuc_url_res if isinstance(nuc_url_res, list) else []
                nuc_ips = nuc_ip_res if isinstance(nuc_ip_res, list) else []
                nuclei = nuc_urls + nuc_ips
                for err in nuclei_errors:
                    report(f"    [!] nuclei call failed: {err}")
                if nuclei_errors:
                    tool_status["nuclei"] = "FAILED"
                else:
                    tool_status["nuclei"] = "OK" if nuclei else "EMPTY"
                save_phase("nuclei", {
                    "urls": nuc_urls, "ips": nuc_ips, "all": nuclei,
                    "errors": nuclei_errors,
                })
                report_progress("6-Nuclei", "completed", len(nuclei))

            update_scan_status(scan_id, "running", nuclei_count=len(nuclei))
            writer.write_nuclei_urls(nuc_urls)
            writer.write_nuclei_ips(nuc_ips)

            cached_p65 = load_phase("js_analysis")
            if cached_p65:
                js_findings = cached_p65.get("findings", [])
                js_endpoints = cached_p65.get("endpoints", [])
                vapt_findings.extend(js_findings)
                report_progress("6.5-JS", "Resumed from cache", len(js_findings))
            else:
                report_progress("6.5-JS", "running")
                js_urls = select_js_urls(crawled, gau_urls, wb_urls, domain)
                if js_urls:
                    js_findings, js_endpoints = await run_js_analysis(
                        js_urls, progress=report)
                else:
                    js_findings, js_endpoints = [], []
                vapt_findings.extend(js_findings)
                save_phase("js_analysis", {
                    "findings": js_findings, "endpoints": js_endpoints,
                })
                report_progress("6.5-JS", "completed", len(js_findings))

            js_lines = [
                f"{f.get('url','')}\t{f.get('vuln_type','')}\t{f.get('evidence','')}"
                for f in (js_findings or [])
            ]
            writer.write_js(js_urls, js_findings, js_lines)
            tool_status["js"] = "OK" if js_findings else "EMPTY"

            for ep in js_endpoints or []:
                if ep.startswith("http"):
                    resolved_endpoints.add(ep)
                elif ep.startswith("/") and live_hosts:
                    for host in live_hosts:
                        resolved_endpoints.add(_urljoin(host, ep))

            vapt_stats = {"attempted": 0, "succeeded": 0, "failed": 0}

            cached_p66 = load_phase("vapt_passive")
            if cached_p66:
                vapt_findings.extend(cached_p66)
                report_progress("6.6-Passive", "Resumed from cache", len(cached_p66))
            else:
                report_progress("6.6-Passive", "running")
                passive = await run_passive_checks(live_hosts, progress=report, stats=vapt_stats)
                file_hits = await run_file_probes(live_hosts, progress=report, stats=vapt_stats)
                combined = passive + file_hits
                vapt_findings.extend(combined)
                save_phase("vapt_passive", combined)
                report_progress("6.6-Passive", "completed", len(combined))

            cached_p67 = load_phase("vapt_active")
            if cached_p67:
                vapt_findings.extend(cached_p67)
                report_progress("6.7-Active", "Resumed from cache", len(cached_p67))
            else:
                report_progress("6.7-Active", "running")
                probe_pool = sorted({
                    u for u in (crawled + gau_urls + wb_urls + list(resolved_endpoints))
                    if _is_interesting_param_url(u, apex)
                })
                param_hits = await run_param_probes(probe_pool, progress=report, stats=vapt_stats)
                vapt_findings.extend(param_hits)
                save_phase("vapt_active", param_hits)
                report_progress("6.7-Active", "completed", len(param_hits))

            if vapt_stats["attempted"] > 0 and vapt_stats["succeeded"] == 0:
                tool_status["vapt"] = "FAILED"
                report(f"    [!] VAPT: all {vapt_stats['attempted']} checks failed")
            else:
                tool_status["vapt"] = "OK" if vapt_findings else "EMPTY"

            update_scan_status(scan_id, "running", vapt_count=len(vapt_findings))
            writer.write_vapt(vapt_findings)

            sqlmap_stats = {"attempted": 0, "succeeded": 0, "failed": 0}
            cached_p7 = load_phase("sqlmap")
            if cached_p7:
                sqli = cached_p7
                report_progress("7-SQLMap", "Resumed from cache", len(sqli))
            else:
                report_progress("7-SQLMap", "running")
                param_pool_raw = {
                    u for u in (crawled + gau_urls + wb_urls + list(resolved_endpoints))
                    if _is_interesting_param_url(u, apex)
                }
                param_pool = sorted({_normalize_params(u) for u in param_pool_raw})
                if param_pool:
                    sqlmap_sem = asyncio.Semaphore(sqlmap_batch_size)

                    async def throttled_sqlmap(u):
                        async with sqlmap_sem:
                            return await run_sqlmap(
                                u, output_root=f"sqlmap_data/{domain}")

                    tasks = [throttled_sqlmap(u) for u in param_pool]
                    results = await asyncio.gather(*tasks, return_exceptions=True)
                    for r in results:
                        sqlmap_stats["attempted"] += 1
                        if isinstance(r, Exception):
                            sqlmap_stats["failed"] += 1
                            report(f"    [!] sqlmap call failed: {str(r)[:200]}")
                            continue
                        sqlmap_stats["succeeded"] += 1
                        if isinstance(r, list):
                            for item in r:
                                if isinstance(item, dict) and item.get("vulnerable"):
                                    sqli.append(item)
                save_phase("sqlmap", sqli)
                report_progress("7-SQLMap", "completed", len(sqli))

            if sqlmap_stats["attempted"] > 0 and sqlmap_stats["succeeded"] == 0:
                tool_status["sqlmap"] = "FAILED"
                report(f"    [!] SQLMap: all {sqlmap_stats['attempted']} calls failed")
            else:
                tool_status["sqlmap"] = "OK" if sqli else "EMPTY"

            update_scan_status(
                scan_id, "running",
                sqli_count=len(sqli), vapt_count=len(vapt_findings),
            )
            tested_urls = param_pool or [
                s["url"] for s in sqli
                if isinstance(s, dict) and s.get("url")
            ]
            writer.write_sqlmap(tested_urls, sqli)

        report_progress("8-Save", "running")
        correlated = correlate_assets(httpx_assets, nmap_assets)

        try:
            _attach_url_intel(
                correlated,
                historical=(gau_urls + wb_urls),
                crawled=crawled,
                discovered_paths=discovered,
                nuclei=nuclei,
                sqli=sqli,
                live_archive_urls=live_archive_urls,
                js_endpoints=sorted(resolved_endpoints),
                logger=report,
                apex=apex,
            )
        except Exception as e:
            report(f"    [!] _attach_url_intel failed (continuing): {e}")

        if vapt_findings:
            try:
                _attach_vapt_findings(correlated, vapt_findings, logger=report, apex=apex)
            except Exception as e:
                report(f"    [!] _attach_vapt_findings failed (continuing): {e}")

        correlated = _dedupe_correlated(correlated)

        for a in correlated:
            a.risk_score, a.risk_summary = calculate_risk(a)

        current_assets = {a.asset_value for a in correlated if a.asset_value}
        prev_active = get_active_asset_count(domain)
        current_count = len(current_assets)

        deactivation_skipped_reason = None
        scan_is_untrusted = False

        if current_count == 0:
            deactivation_skipped_reason = (
                f"scan produced 0 assets (previously {prev_active} active)")
            scan_is_untrusted = True
        elif prev_active > 0 and current_count < prev_active:
            loss_rate = 1.0 - (current_count / prev_active)
            if loss_rate > 0.5:
                deactivation_skipped_reason = (
                    f"scan lost {int(loss_rate * 100)}% of active assets")
                scan_is_untrusted = True

        if scan_is_untrusted:
            report(f"    [!] SAFETY NET TRIGGERED: {deactivation_skipped_reason}")
            report(f"    [!] Skipping asset deactivation (kept as active) — "
                   f"findings WILL still be saved.")
        else:
            deactivate_missing_assets(current_assets, domain, scanned_hosts=all_subs)

        saved = 0
        save_failures = []
        for a in correlated:
            if not a.asset_value or not a.asset_value.strip():
                report("    [!] Skipping asset with empty asset_value")
                continue

            last_err = None
            for attempt in (1, 2):
                try:
                    save_asset_to_db(a, scan_id, mode=mode, tool_status=tool_status)
                    saved += 1
                    last_err = None
                    break
                except Exception as e:
                    last_err = str(e)
                    if attempt == 1:
                        report(f"    [~] save attempt 1 failed for {a.asset_value} ({last_err[:80]}); retrying")
                        await asyncio.sleep(0.5)
                    else:
                        save_failures.append((a.asset_value, last_err))
                        report(f"    [!] DB save failed for {a.asset_value} after 2 attempts: {e}")

        verification_shortfall = _verify_scan_save(
            scan_id, correlated, mode, report, tool_status)

        pending_ai = sum(1 for a in correlated if a.risk_score >= AI_RISK_THRESHOLD)

        warnings = []
        if save_failures:
            summary = "; ".join(f"{h}: {e[:80]}" for h, e in save_failures[:5])
            warnings.append(
                f"{len(save_failures)}/{len(correlated)} asset saves failed — {summary}")
        if verification_shortfall:
            warnings.append(verification_shortfall)
        if deactivation_skipped_reason:
            warnings.append(f"deactivation skipped: {deactivation_skipped_reason}")
        if mode == "full" and tool_status.get("nuclei") == "FAILED":
            warnings.append("nuclei failed; prior findings preserved")
        if mode == "full" and tool_status.get("vapt") == "FAILED":
            warnings.append("VAPT failed; prior findings preserved")
        if mode == "full" and tool_status.get("sqlmap") == "FAILED":
            warnings.append("sqlmap failed; prior findings preserved")

        if len(correlated) == 0:
            final_status = "failed"
            final_error = "scan produced no assets"
        elif warnings:
            final_status = "partial"
            final_error = "; ".join(warnings)
        else:
            final_status = "completed"
            final_error = None

        try:
            update_scan_status(
                scan_id, final_status, completed_at=datetime.now(),
                correlated_asset_count=len(correlated), saved_asset_count=saved,
                error_message=final_error,
                tool_status_json=json.dumps(tool_status),
            )
        except Exception as e:
            report(f"    [!] Failed to update final scan status in DB: {e}")

        report_progress("8-Save", "completed", saved)

        if enrich_ai and pending_ai > 0:
            report_progress("9-AI", "Queued", pending_ai)
            from core.enricher import enrich_scan
            import re as _re

            def ai_progress(msg):
                report(msg)
                session = SessionLocal()
                try:
                    prog = session.query(ScanProgressModel).filter_by(
                        scan_id=scan_id, phase="9-AI").first()
                    if not prog:
                        prog = ScanProgressModel(
                            scan_id=scan_id, phase="9-AI",
                            status="running", count=0)
                        session.add(prog)
                    prog.status = "running"
                    match = _re.search(r"\[(\d+)/(\d+)\]", msg)
                    if match:
                        prog.count = int(match.group(1))
                    session.commit()
                except Exception:
                    session.rollback()
                finally:
                    session.close()

            if wait_for_enrichment:
                try:
                    enrich_scan(scan_id, ai_progress)
                    report("    AI enrichment completed synchronously.")
                except Exception as e:
                    report(f"    [!] AI enrichment failed: {e}")
            else:
                threading.Thread(
                    target=enrich_scan,
                    args=(scan_id, ai_progress),
                    daemon=True,
                ).start()
                report("    Scan complete. AI enrichment is running in the background.")

        elif pending_ai:
            report_progress("9-AI", f"{pending_ai} pending", pending_ai)
            report(f"    {pending_ai} assets pending AI enrichment — "
                   f"run `python enrich.py --scan-id {scan_id}`")

        report(f"\n[+] DYNAMO finished [{final_status}] — "
               f"saved {saved}/{len(correlated)} assets\n")
        return {
            "scan_id": scan_id, "assets_saved": saved,
            "mode": mode, "status": final_status,
        }

    except Exception as e:
        report(f"\n[!] Pipeline failed for {domain}: {e}\n")
        update_scan_status(scan_id, "failed", error_message=str(e)[:2000])
        raise