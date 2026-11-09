from schemas.asset import Asset, Service
from core.risk_engine import calculate_risk
from core.cve_lookup import lookup_cves


def _safe_int(val, default=0):
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default


def normalize_nmap(nmap_results):
    if not isinstance(nmap_results, list):
        nmap_results = []

    grouped = {}
    for item in nmap_results:
        if not isinstance(item, dict):
            continue
        ip = item.get("ip")
        if not ip:
            continue
        grouped.setdefault(ip, []).append(item)

    assets = []
    for ip, port_entries in grouped.items():
        services = []
        detected_technologies = set()

        for entry in port_entries:
            port_num = _safe_int(entry.get("port"), default=0)
            if port_num == 0:
                continue

            protocol = entry.get("protocol") or "tcp"
            service_name = entry.get("service") or "unknown"
            product = entry.get("product")
            version = entry.get("version")

            if product:
                tech_str = f"{product}:{version}".strip() if version else product
                detected_technologies.add(tech_str)

            services.append(Service(
                port=port_num,
                protocol=protocol,
                service_name=service_name,
                product=product,
                version=version,
            ))

        tech_list = list(detected_technologies)

        asset = Asset(
            asset_value=ip,
            resolved_ips=[ip],
            technologies=tech_list,
            services=services,
        )

        asset.cves = lookup_cves(tech_list)
        asset.risk_score, asset.risk_summary = calculate_risk(asset)
        assets.append(asset)

    return assets