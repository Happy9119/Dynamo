import asyncio

from vapt.http_client import build_session
from vapt.js_analysis import analyze_js_url, collect_js_urls
from vapt import (
    headers_check, sensitive_files, cors_check, methods_check, param_probes,
)


async def run_js_analysis(js_urls, progress=None, concurrency=20):
    if not js_urls:
        return [], []

    findings = []
    endpoints = set()
    sem = asyncio.Semaphore(concurrency)

    async def worker(session, url):
        async with sem:
            return await analyze_js_url(session, url)

    session = build_session(concurrency)
    try:
        tasks = [worker(session, u) for u in js_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                continue
            f, e = r
            findings.extend(f)
            endpoints.update(e)
    finally:
        await session.close()

    if progress:
        progress(f"    js_files={len(js_urls)} findings={len(findings)} "
                 f"endpoints={len(endpoints)}")

    return findings, sorted(endpoints)


async def run_passive_checks(urls, progress=None, concurrency=15, stats=None):
    if not urls:
        return []

    if stats is None:
        stats = {}
    stats.setdefault("attempted", 0)
    stats.setdefault("succeeded", 0)
    stats.setdefault("failed", 0)

    findings = []
    sem = asyncio.Semaphore(concurrency)

    async def one(session, url):
        async with sem:
            stats["attempted"] += 1
            batch = []
            try:
                batch.extend(await headers_check.check_url(session, url))
                batch.extend(await cors_check.check_url(session, url))
                batch.extend(await methods_check.check_url(session, url))
                stats["succeeded"] += 1
            except Exception:
                stats["failed"] += 1
            return batch

    session = build_session(concurrency)
    try:
        tasks = [one(session, u) for u in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                stats["failed"] += 1
                continue
            findings.extend(r)
    finally:
        await session.close()

    if progress:
        progress(f"    passive_urls={len(urls)} findings={len(findings)}")
    return findings


async def run_file_probes(base_urls, progress=None, concurrency=8, stats=None):
    if not base_urls:
        return []

    if stats is None:
        stats = {}
    stats.setdefault("attempted", 0)
    stats.setdefault("succeeded", 0)
    stats.setdefault("failed", 0)

    findings = []
    sem = asyncio.Semaphore(concurrency)

    async def one(session, url):
        async with sem:
            stats["attempted"] += 1
            try:
                result = await sensitive_files.check_host(session, url)
                stats["succeeded"] += 1
                return result
            except Exception:
                stats["failed"] += 1
                return []

    session = build_session(concurrency)
    try:
        tasks = [one(session, u) for u in base_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                stats["failed"] += 1
                continue
            findings.extend(r)
    finally:
        await session.close()

    if progress:
        progress(f"    file_probed_hosts={len(base_urls)} findings={len(findings)}")
    return findings


async def run_param_probes(param_urls, progress=None, concurrency=10, stats=None):
    if not param_urls:
        return []

    if stats is None:
        stats = {}
    stats.setdefault("attempted", 0)
    stats.setdefault("succeeded", 0)
    stats.setdefault("failed", 0)

    findings = []
    sem = asyncio.Semaphore(concurrency)

    async def one(session, url):
        async with sem:
            stats["attempted"] += 1
            try:
                result = await param_probes.probe_url(session, url)
                stats["succeeded"] += 1
                return result
            except Exception:
                stats["failed"] += 1
                return []

    session = build_session(concurrency)
    try:
        tasks = [one(session, u) for u in param_urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                stats["failed"] += 1
                continue
            findings.extend(r)
    finally:
        await session.close()

    if progress:
        progress(f"    param_urls={len(param_urls)} findings={len(findings)}")
    return findings


def select_js_urls(crawled, gau_urls, wb_urls, base_url):
    return collect_js_urls(
        list(crawled) + list(gau_urls) + list(wb_urls),
        base_url,
    )