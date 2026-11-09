import os

_MULTI_SUFFIXES = {
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "org.nz", "net.nz",
    "co.in", "net.in", "org.in", "firm.in", "gen.in", "ind.in",
    "ac.in", "edu.in", "gov.in", "res.in",
    "co.za", "org.za",
    "com.br", "net.br", "org.br",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "ne.kr",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.hk", "org.hk", "edu.hk", "gov.hk",
    "com.sg", "net.sg", "org.sg", "edu.sg", "gov.sg",
    "com.de", "com.fr", "com.es", "com.it", "com.nl", "com.pl", "com.ru",
    "co.il", "org.il", "ac.il", "gov.il",
    "com.tr", "com.mx", "com.ar", "com.co", "com.pe", "com.ve",
    "co.id", "or.id", "ac.id", "go.id",
}

_EXTRA = os.environ.get("DYNAMO_EXTRA_SUFFIXES", "").strip()
if _EXTRA:
    for s in _EXTRA.split(","):
        s = s.strip().lower()
        if s:
            _MULTI_SUFFIXES.add(s)


def _max_suffix_depth():
    if not _MULTI_SUFFIXES:
        return 0
    return max(len(s.split(".")) for s in _MULTI_SUFFIXES)


def extract_apex(host: str) -> str | None:
    if not host:
        return None

    host = host.strip().lower().rstrip(".")

    if "//" in host:
        host = host.split("//", 1)[1]
        host = host.split("/", 1)[0]

    if ":" in host:
        host = host.split(":", 1)[0]

    if "." not in host:
        return None

    parts = host.split(".")

    max_depth = _max_suffix_depth()
    for n in range(max_depth, 1, -1):
        if len(parts) > n:
            candidate = ".".join(parts[-n:])
            if candidate in _MULTI_SUFFIXES:
                return ".".join(parts[-(n + 1):])

    if len(parts) >= 2:
        tail2 = ".".join(parts[-2:])
        if tail2 in _MULTI_SUFFIXES:
            return None
        return tail2

    return None


def host_belongs_to_apex(host: str, apex: str) -> bool:
    if not host or not apex:
        return False
    h = host.strip().lower().rstrip(".")
    a = apex.strip().lower().rstrip(".")
    return h == a or h.endswith("." + a)