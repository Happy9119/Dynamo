import xml.etree.ElementTree as ET


def parse_nmap_xml(xml_data):
    results = []
    if not xml_data:
        return results

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        print(f"[!] Failed to parse Nmap XML: {e}")
        return results

    for host in root.findall("host"):
        ip_addr = None
        for addr in host.findall("address"):
            if addr.get("addrtype") in ("ipv4", "ipv6"):
                ip_addr = addr.get("addr")
                break

        if not ip_addr:
            continue

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            results.append({
                "ip": ip_addr,
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "service": service.get("name") if service is not None else None,
                "product": service.get("product") if service is not None else None,
                "version": service.get("version") if service is not None else None,
            })

    return results