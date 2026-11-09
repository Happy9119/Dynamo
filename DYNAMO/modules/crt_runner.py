import aiohttp

from config.tools import CRT_API_URL


async def run_crt(domain: str, progress=None) -> list[str]:
    def _log(msg):
        if progress:
            progress(msg)
        else:
            print(msg)
    url = CRT_API_URL.format(domain=domain)
    try:
        timeout = aiohttp.ClientTimeout(total=30)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(url) as resp:
                if resp.status != 200:
                    print(f"[!] crt.name status {resp.status}")
                    return []
                text = await resp.text()
    except Exception as e:
        print(f"[!] crt.name failed: {e}")
        return []

    base = domain.strip().lower().rstrip(".")
    suffix = "." + base
    
    cleaned = set()
    for line in text.splitlines():
        line = line.strip().lower().rstrip(".")
        if not line:
            continue
        if line == base or line.endswith(suffix):
            cleaned.add(line)
    return sorted(cleaned)