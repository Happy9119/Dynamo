from sqlalchemy import text
from storage.database import engine


def _count(sql: str, scan_id: int) -> int:
    with engine.connect() as c:
        return int(c.execute(text(sql), {"sid": int(scan_id)}).scalar() or 0)


def count_subdomains(scan_id: int) -> int:
    return _count(
        "SELECT COUNT(DISTINCT asset_id) FROM scan_assets WHERE scan_id = :sid",
        scan_id)


def count_services(scan_id: int) -> int:
    return _count("""
        SELECT COUNT(*) FROM services s
        JOIN scan_assets sa ON sa.asset_id = s.asset_id
        WHERE sa.scan_id = :sid
    """, scan_id)


def count_cves(scan_id: int) -> int:
    return _count("""
        SELECT COUNT(*) FROM asset_cves c
        JOIN scan_assets sa ON sa.asset_id = c.asset_id
        WHERE sa.scan_id = :sid
    """, scan_id)


def count_nuclei(scan_id: int) -> int:
    return _count("""
        SELECT COUNT(*) FROM nuclei_findings n
        JOIN scan_assets sa ON sa.asset_id = n.asset_id
        WHERE sa.scan_id = :sid
    """, scan_id)


def count_sqli(scan_id: int) -> int:
    return _count("""
        SELECT COUNT(*) FROM sqli_findings q
        JOIN scan_assets sa ON sa.asset_id = q.asset_id
        WHERE sa.scan_id = :sid
    """, scan_id)