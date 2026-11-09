from schemas.asset import Asset, Service
from core.risk_engine import calculate_risk
from core.cve_lookup import lookup_cves


def normalize_httpx(data):
    technologies = data.get("tech", []) or []
    host_ip = data.get("host_ip") or data.get("ip")
    resolved_ips = [host_ip] if host_ip else []

    scheme = (data.get("scheme") or "").lower()
    if not scheme:
        url_hint = (data.get("url") or "").lower()
        scheme = "https" if url_hint.startswith("https://") else "http"
    is_https = (scheme == "https")

    raw_port = data.get("port")
    default_port = 443 if is_https else 80
    try:
        port_num = int(raw_port) if raw_port is not None else default_port
    except (ValueError, TypeError):
        port_num = default_port

    service_name = "https" if is_https else "http"

    service = Service(
        port=port_num,
        protocol="tcp",
        service_name=service_name,
        webserver=data.get("webserver"),
        technologies=technologies,
    )

    asset = Asset(
        asset_value=data.get("input") or data.get("url") or host_ip,
        resolved_ips=resolved_ips,
        url=data.get("url"),
        title=data.get("title"),
        status_code=data.get("status_code"),
        cdn_name=data.get("cdn_name"),
        technologies=technologies,
        services=[service],
    )

    asset.cves = lookup_cves(technologies)
    asset.risk_score, asset.risk_summary = calculate_risk(asset)
    return asset