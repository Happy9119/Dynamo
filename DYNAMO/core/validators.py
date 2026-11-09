import ipaddress
import re

LABEL = r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
HOSTNAME_PATTERN = re.compile(rf"^(?:{LABEL}\.)*{LABEL}$")


def is_valid_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    if hostname.endswith("."):
        hostname = hostname[:-1]
    if ".." in hostname or hostname.startswith("-") or hostname.endswith("-"):
        return False

    try:
        ipaddress.ip_address(hostname)
        return False
    except ValueError:
        pass

    return bool(HOSTNAME_PATTERN.match(hostname))


def is_safe_path_component(name: str) -> bool:
    if not name or not isinstance(name, str):
        return False
    if "/" in name or "\\" in name:
        return False
    if name in (".", ".."):
        return False
    if name.startswith("."):
        return False
    if "\x00" in name:
        return False
    return True