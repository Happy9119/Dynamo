import aiohttp

DEFAULT_TIMEOUT = 10
DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; DYNAMO/1.0)"
}


def build_session(concurrency=20):
    connector = aiohttp.TCPConnector(limit=concurrency)
    timeout = aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT)
    return aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers=DEFAULT_HEADERS,
    )