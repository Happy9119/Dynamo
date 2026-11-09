import argparse
import sys

try:
    import resource
    _soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(8192, _hard), _hard))
except Exception:
    pass

from core.enricher import enrich_all, enrich_domain, enrich_scan
from core.domain_utils import extract_apex
from storage.database import SessionLocal
from storage.models import DomainModel


def _resolve_domain_id(apex: str) -> int | None:
    session = SessionLocal()
    try:
        d = session.query(DomainModel).filter_by(apex=apex).first()
        return d.id if d else None
    finally:
        session.close()


def main():
    ap = argparse.ArgumentParser(prog="dynamo-enrich",
                                 description="Run AI enrichment on pending assets.")
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--scan-id", type=int, help="Enrich assets from one scan")
    grp.add_argument("--domain",  type=str, help="Enrich assets under one apex")
    grp.add_argument("--all",     action="store_true", help="Enrich everything pending")
    ap.add_argument("--risk-min", type=int, default=20,
                    help="Only enrich assets at or above this risk score")
    ap.add_argument("--limit",    type=int, default=None,
                    help="Only process the first N pending assets")
    args = ap.parse_args()

    if args.scan_id is not None:
        print(f"[*] Enriching scan #{args.scan_id} (risk_min={args.risk_min})")
        summary = enrich_scan(args.scan_id, risk_min=args.risk_min)

    elif args.domain:
        apex = extract_apex(args.domain)
        if not apex:
            print(f"[!] Could not parse an apex from {args.domain!r}")
            sys.exit(1)
        domain_id = _resolve_domain_id(apex)
        if domain_id is None:
            print(f"[!] Domain {apex!r} not in database. Run a scan first.")
            sys.exit(1)
        print(f"[*] Enriching {apex} (risk_min={args.risk_min})")
        summary = enrich_domain(domain_id, risk_min=args.risk_min)

    else:
        print(f"[*] Enriching all pending assets (risk_min={args.risk_min})")
        summary = enrich_all(risk_min=args.risk_min, limit=args.limit)

    print()
    if summary["total"] == 0:
        print("[+] Nothing to enrich — all qualifying assets are already done.")
        return

    print(f"[+] Complete in {summary['elapsed_sec']}s")
    print(f"    enriched: {summary['enriched']}")
    print(f"    skipped:  {summary['skipped']}  (below risk_min)")
    print(f"    failed:   {summary['failed']}")


if __name__ == "__main__":
    main()