import aiohttp

from config.tools import WAYBACK_TIMEOUT


async def run_wayback(domain: str, limit: int = 100000, progress=None) -> list[str]:
    def _log(msg):
        if progress:
            progress(msg)
        else:
            print(msg)
    url = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={domain}&matchType=domain&fl=original"
        f"&collapse=urlkey&limit={limit}"
    )
    try:
        timeout = aiohttp.ClientTimeout(total=WAYBACK_TIMEOUT)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    print(f"[!] Wayback status {resp.status}")
                    return []
                text = await resp.text()
    except Exception as e:
        print(f"[!] Wayback failed: {e}")
        return []

    return sorted({l.strip() for l in text.splitlines() if l.strip()})