from copy import deepcopy


def _merge_service_into(existing, nmap_asset):
    index = {(s.port, s.protocol): s for s in existing.services}

    for svc in nmap_asset.services:
        key = (svc.port, svc.protocol)
        if key not in index:
            existing.services.append(deepcopy(svc))
            index[key] = existing.services[-1]
        else:
            cur = index[key]
            if svc.product:
                if not cur.product or cur.product.lower().strip() in ("unknown", ""):
                    cur.product = svc.product
                elif (
                    cur.product.lower() in svc.product.lower()
                    and len(svc.product) > len(cur.product)
                ):
                    cur.product = svc.product
            if svc.version:
                if not cur.version:
                    cur.version = svc.version
            if svc.service_name and svc.service_name != "unknown" \
                    and (not cur.service_name
                         or cur.service_name in ("http", "unknown")):
                cur.service_name = svc.service_name


def _merge_tech_and_cves_into(existing, nmap_asset):
    for tech in nmap_asset.technologies:
        if tech not in existing.technologies:
            existing.technologies.append(tech)

    existing_cve_ids = {c.get("cve") for c in existing.cves if c.get("cve")}
    for cve in nmap_asset.cves:
        if cve.get("cve") and cve.get("cve") not in existing_cve_ids:
            existing.cves.append(deepcopy(cve))


def _merge_httpx_assets(existing, incoming):
    existing_keys = {(s.port, s.protocol) for s in existing.services}
    for svc in incoming.services:
        if (svc.port, svc.protocol) not in existing_keys:
            existing.services.append(deepcopy(svc))
            existing_keys.add((svc.port, svc.protocol))

    for tech in incoming.technologies:
        if tech not in existing.technologies:
            existing.technologies.append(tech)

    for ip in incoming.resolved_ips:
        if ip not in existing.resolved_ips:
            existing.resolved_ips.append(ip)

    if not existing.title and incoming.title:
        existing.title = incoming.title
    if not existing.url and incoming.url:
        existing.url = incoming.url
    if not existing.status_code and incoming.status_code:
        existing.status_code = incoming.status_code


def correlate_assets(httpx_assets, nmap_assets):
    correlated = {}
    for asset in httpx_assets:
        key = asset.asset_value
        if key in correlated:
            _merge_httpx_assets(correlated[key], asset)
        else:
            correlated[key] = deepcopy(asset)

    unmatched_nmap = []

    for nmap_asset in nmap_assets:
        nmap_ip = nmap_asset.asset_value
        matches = sorted(
            [a for a in correlated.values() if nmap_ip in a.resolved_ips],
            key=lambda a: a.asset_value.lower(),
        )

        if matches:
            if len(matches) > 1:
                print(
                    f"[!] correlate: nmap {nmap_ip} maps to "
                    f"{len(matches)} vhosts — attaching to "
                    f"{matches[0].asset_value}"
                )
            _merge_service_into(matches[0], nmap_asset)
            _merge_tech_and_cves_into(matches[0], nmap_asset)
        else:
            unmatched_nmap.append(nmap_asset)

    for orphan in unmatched_nmap:
        if orphan.asset_value not in correlated:
            correlated[orphan.asset_value] = orphan
        else:
            target = correlated[orphan.asset_value]
            _merge_service_into(target, orphan)
            _merge_tech_and_cves_into(target, orphan)

    return list(correlated.values())