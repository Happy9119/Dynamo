import json
from pathlib import Path
from core.tech_utils import parse_tech_string

CVE_DB_PATH = Path("data/cves/cve_map.json")
_cve_db_cache = None

TECH_ALIASES = {
    "apache": "apache http server",
    "apache http server": "apache http server",
    "php": "php",
    "iis": "iis",
    "microsoft iis": "iis",
    "asp.net": "microsoft asp.net",
    "microsoft asp.net": "microsoft asp.net",
    "nginx": "nginx",
    "wordpress": "wordpress",
    "jenkins": "jenkins",
}


def _normalize_name(name):
    if not name:
        return ""
    normalized = " ".join(name.lower().strip().split())
    return TECH_ALIASES.get(normalized, normalized)


def _normalize_version(version):
    return version.strip() if version else None


def load_cve_database():
    global _cve_db_cache
    if _cve_db_cache is None:
        try:
            with open(CVE_DB_PATH, "r") as f:
                _cve_db_cache = json.load(f)
        except FileNotFoundError:
            print(f"[!] CVE database not found at {CVE_DB_PATH}, using empty set")
            _cve_db_cache = {}
        except json.JSONDecodeError as e:
            print(f"[!] CVE database is not valid JSON: {e}")
            _cve_db_cache = {}
    return _cve_db_cache


def _is_version_prefix(shorter, longer):
    if not longer.startswith(shorter):
        return False
    if len(longer) == len(shorter):
        return True
    next_char = longer[len(shorter)]
    return next_char in (".", "-", "_", "+")


def _classify_match(detected, db_ver):
    if detected == db_ver:
        return "exact_product_version", "high"

    if _is_version_prefix(detected, db_ver):
        return "partial_detected_prefix_of_db", "medium"

    if _is_version_prefix(db_ver, detected):
        return "partial_db_prefix_of_detected", "medium"

    return None, None


def lookup_cves(technologies):
    cve_db = load_cve_database()
    matched = {}

    for tech in technologies:
        if not tech:
            continue

        detected_name, detected_version = parse_tech_string(tech)
        normalized_name = _normalize_name(detected_name)
        normalized_version = _normalize_version(detected_version)

        if not normalized_name:
            continue

        for db_key, entries in cve_db.items():
            db_name, db_version = parse_tech_string(db_key)
            if _normalize_name(db_name) != normalized_name:
                continue

            if normalized_version and db_version:
                match_type, confidence = _classify_match(
                    normalized_version, db_version)
                if not match_type:
                    continue
            elif db_version and not normalized_version:
                match_type, confidence = "name_only_detected", "low"
            elif normalized_version and not db_version:
                match_type, confidence = "name_only_db", "low"
            else:
                match_type, confidence = "name_only_both", "low"

            _CONF_RANK = {"high": 3, "medium": 2, "low": 1}

            for entry in entries:
                cve_id = entry.get("cve")
                if not cve_id:
                    continue
                existing = matched.get(cve_id)
                if existing:
                    if _CONF_RANK.get(existing["match_confidence"], 0) >= \
                       _CONF_RANK.get(confidence, 0):
                        continue
                matched[cve_id] = {
                    **entry,
                    "match_type": match_type,
                    "match_confidence": confidence,
                    "detected_technology": detected_name,
                    "detected_version": detected_version,
                }

    return list(matched.values())


def lookup_from_nuclei(nuclei_findings):
    import re
    cve_re = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.IGNORECASE)
    seen = set()
    results = []

    for f in nuclei_findings or []:
        template_id = getattr(f, "template_id", "") or ""
        name = getattr(f, "name", "") or ""
        description = getattr(f, "description", "") or ""
        severity = (getattr(f, "severity", "") or "").lower()
        matched_at = getattr(f, "matched_at", "") or ""

        haystack = f"{template_id} {name} {description}"
        for match in cve_re.findall(haystack):
            cve_id = match.upper()
            if cve_id in seen:
                continue
            seen.add(cve_id)
            results.append({
                "cve": cve_id,
                "severity": severity or "medium",
                "cvss": None,
                "description": name or f"Detected via nuclei template {template_id}",
                "match_confidence": "high",
                "source": "nuclei",
                "matched_at": matched_at,
            })

    return results