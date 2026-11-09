def parse_tech_string(tech):
    if not tech:
        return "", None
    if ":" in tech:
        name, version = tech.split(":", 1)
        return name.strip(), (version.strip() or None)
    return tech.strip(), None


def format_tech_string(name, version=None):
    if not name:
        return ""
    return f"{name.strip()}:{version.strip()}" if version else name.strip()