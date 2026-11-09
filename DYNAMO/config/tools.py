import os
import shutil

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def _resolve_bin(env_name, default_name):
    explicit = os.environ.get(env_name)
    if explicit:
        if os.path.isfile(explicit) and os.access(explicit, os.X_OK):
            return explicit

        print(f"[!] {env_name}={explicit!r} is missing or not executable")

        found = shutil.which(default_name)
        if found:
            print(f"[+] {env_name} falling back to {found} from PATH")
            return found

        return explicit

    found = shutil.which(default_name)
    return found if found else default_name


SUBFINDER_BIN = _resolve_bin("SUBFINDER_BIN", "subfinder")
HTTPX_BIN     = _resolve_bin("HTTPX_BIN", "httpx")
NMAP_BIN      = _resolve_bin("NMAP_BIN", "nmap")
GAU_BIN       = _resolve_bin("GAU_BIN", "gau")
KATANA_BIN    = _resolve_bin("KATANA_BIN", "katana")
NUCLEI_BIN    = _resolve_bin("NUCLEI_BIN", "nuclei")
FFUF_BIN      = _resolve_bin("FFUF_BIN", "ffuf")
SQLMAP_BIN    = _resolve_bin("SQLMAP_BIN", "sqlmap")

WAYBACK_TIMEOUT = int(os.environ.get("WAYBACK_TIMEOUT", "900"))
CRT_API_URL     = os.environ.get(
    "CRT_API_URL", "https://crt.name/v1/search?apex={domain}"
)

DIRLIST_PATH = os.environ.get("DIRLIST_PATH", "dirlist.txt")

NMAP_TIMEOUT     = int(os.environ.get("NMAP_TIMEOUT", "900"))
NMAP_CONCURRENCY = int(os.environ.get("NMAP_CONCURRENCY", "5"))

NMAP_PORTS = os.environ.get(
    "NMAP_PORTS",
    "21,22,23,25,53,80,88,110,139,143,389,443,445,465,"
    "587,636,993,995,3306,3389,3268,3269,5432,5900,"
    "6379,8000,8080,8443,8888,9200,27017,50389",
)

AI_RISK_THRESHOLD = int(os.environ.get("AI_RISK_THRESHOLD", "20"))
HTTPX_TIMEOUT    = int(os.environ.get("HTTPX_TIMEOUT", "900"))
HTTPX_BULK_TIMEOUT = int(os.environ.get("HTTPX_BULK_TIMEOUT", "1800"))
FFUF_TIMEOUT     = int(os.environ.get("FFUF_TIMEOUT", "900"))
NUCLEI_TIMEOUT   = int(os.environ.get("NUCLEI_TIMEOUT", "9000"))
KATANA_TIMEOUT   = int(os.environ.get("KATANA_TIMEOUT", "9000"))
SUBFINDER_TIMEOUT = int(os.environ.get("SUBFINDER_TIMEOUT", "900"))
GAU_TIMEOUT      = int(os.environ.get("GAU_TIMEOUT", "9000"))
SQLMAP_LEVEL = int(os.environ.get("SQLMAP_LEVEL", "1"))
SQLMAP_RISK  = int(os.environ.get("SQLMAP_RISK", "1"))
SQLMAP_TIMEOUT = int(os.environ.get("SQLMAP_TIMEOUT", "300"))

NUCLEI_CONCURRENCY = int(os.environ.get("NUCLEI_CONCURRENCY", "50"))
HTTPX_CONCURRENCY = int(os.environ.get("HTTPX_CONCURRENCY", "150"))

TRIAGE_MODEL = os.environ.get("TRIAGE_MODEL", "phi3:mini")
DEEP_MODEL = os.environ.get("DEEP_MODEL", "mistral")

HTTPX_RATE_LIMIT = int(os.environ.get("HTTPX_RATE_LIMIT", "150"))
NUCLEI_RATE_LIMIT = int(os.environ.get("NUCLEI_RATE_LIMIT", "150"))