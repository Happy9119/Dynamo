import asyncio
import json
import os
import tempfile

from config.tools import HTTPX_BIN, HTTPX_TIMEOUT
from modules._subprocess_utils import communicate_with_timeout


async def run_httpx(subdomains):
    if not subdomains:
        return []

    fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "w") as tmp:
            for sub in subdomains:
                tmp.write(sub + "\n")

        try:
            process = await asyncio.create_subprocess_exec(
                HTTPX_BIN, "-silent", "-json", "-title",
                "-tech-detect", "-status-code", "-ip", "-cdn",
                "-l", temp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            stdout, stderr = await communicate_with_timeout(process, HTTPX_TIMEOUT)
        except FileNotFoundError as e:
            raise RuntimeError(f"Could not execute httpx at '{HTTPX_BIN}'") from e
        except TimeoutError as e:
            raise RuntimeError(f"httpx timeout: {e}") from e

        if process.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise RuntimeError(f"httpx exit {process.returncode}: {err}")

        results = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    results.append(data)
            except json.JSONDecodeError:
                pass
        return results
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


async def probe_urls(urls, mc=None, timeout=None):
    if not urls:
        return []

    effective_timeout = timeout if timeout is not None else HTTPX_TIMEOUT

    fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "w") as tmp:
            for u in urls:
                tmp.write(u + "\n")

        cmd = [HTTPX_BIN, "-silent", "-json", "-title",
               "-tech-detect", "-status-code", "-ip", "-cdn",
               "-l", temp_path]
        if mc:
            cmd.extend(["-mc", mc])

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            stdout, stderr = await communicate_with_timeout(process, effective_timeout)
        except FileNotFoundError as e:
            raise RuntimeError(f"Could not execute httpx at '{HTTPX_BIN}'") from e
        except TimeoutError as e:
            raise RuntimeError(f"httpx timeout after {effective_timeout}s: {e}") from e

        if process.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise RuntimeError(f"httpx exit {process.returncode}: {err}")

        results = []
        for line in stdout.decode(errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                if isinstance(data, dict):
                    results.append(data)
            except json.JSONDecodeError:
                pass
        return results
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)


async def check_urls_live(urls, timeout=None):
    if not urls:
        return []

    effective_timeout = timeout if timeout is not None else HTTPX_TIMEOUT

    fd, temp_path = tempfile.mkstemp()
    try:
        with os.fdopen(fd, "w") as tmp:
            for u in urls:
                tmp.write(u + "\n")

        from config.tools import HTTPX_CONCURRENCY, HTTPX_RATE_LIMIT
        cmd = [
            HTTPX_BIN,
            "-silent",
            "-mc", "200",
            "-threads", str(HTTPX_CONCURRENCY),
            "-rate-limit", str(HTTPX_RATE_LIMIT), # <-- NEW
            "-timeout", "5",
            "-retries", "0",
            "-l", temp_path,
        ]

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            stdout, stderr = await communicate_with_timeout(
                process, effective_timeout)
        except FileNotFoundError as e:
            raise RuntimeError(f"Could not execute httpx at '{HTTPX_BIN}'") from e
        except TimeoutError as e:
            raise RuntimeError(
                f"httpx liveness timeout after {effective_timeout}s: {e}"
            ) from e

        if process.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise RuntimeError(f"httpx exit {process.returncode}: {err}")

        return [
            line.strip()
            for line in stdout.decode(errors="replace").splitlines()
            if line.strip()
        ]
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)