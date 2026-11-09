from sqlalchemy import text
from storage.database import engine


INDEXES = [
    ("ix_services_asset_id",       "services",          "asset_id"),
    ("ix_asset_cves_asset_id",     "asset_cves",        "asset_id"),
    ("ix_change_events_asset_id",  "change_events",     "asset_id"),
    ("ix_asset_vulns_asset_id",    "asset_vulns",       "asset_id"),
    ("ix_nuclei_findings_asset_id", "nuclei_findings",  "asset_id"),
    ("ix_sqli_findings_asset_id",  "sqli_findings",     "asset_id"),
    ("ix_asset_ips_asset_id",      "asset_ips",         "asset_id"),
    ("ix_asset_urls_asset_id",     "asset_urls",        "asset_id"),
    ("ix_asset_observations_asset_id", "asset_observations", "asset_id"),
    ("ix_asset_observations_scan_id",  "asset_observations", "scan_id"),
    ("ix_assets_ip_address",       "assets",            "ip_address"),
    ("ix_assets_domain_id",        "assets",            "domain_id"),
]


def main():
    with engine.begin() as conn:
        for name, table, column in INDEXES:
            existing = conn.execute(text(
                "SELECT 1 FROM pg_indexes WHERE indexname = :name"
            ), {"name": name}).first()

            if existing:
                print(f"[=] {name} already exists")
                continue

            print(f"[+] Creating {name} on {table}({column})")
            conn.execute(text(
                f"CREATE INDEX IF NOT EXISTS {name} ON {table} ({column})"
            ))

    print("[+] Done.")


if __name__ == "__main__":
    main()