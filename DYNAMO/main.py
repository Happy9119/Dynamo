import argparse
import asyncio

try:
    import resource
    _soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(8192, _hard), _hard))
except Exception:
    pass

from core.orchestrator import run_pipeline
from core.validators import is_valid_hostname


async def main():
    ap = argparse.ArgumentParser(prog="dynamo")
    ap.add_argument("domain", nargs="?", help="target domain, e.g. example.com")
    ap.add_argument("--full", action="store_true",
                    help="run full recon (katana + ffuf + nuclei + sqlmap)")
    ap.add_argument("--enrich", action="store_true",
                    help="run AI enrichment inline after scan")
    ap.add_argument("--fresh", action="store_true",
                    help="force a new scan; never resume a prior interrupted/abandoned scan")
    args = ap.parse_args()

    domain = args.domain or input("\nEnter target domain: ").strip()
    if not domain or not is_valid_hostname(domain):
        print("[!] Invalid domain. Example: example.com")
        return

    await run_pipeline(
        domain,
        mode="full" if args.full else "quick",
        enrich_ai=args.enrich,
        wait_for_enrichment=args.enrich,
        fresh=args.fresh,
    )

if __name__ == "__main__":
    asyncio.run(main())