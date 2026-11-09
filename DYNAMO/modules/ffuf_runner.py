import asyncio
import json
import os
import shutil

from config.tools import FFUF_BIN, DIRLIST_PATH, FFUF_TIMEOUT
from modules._subprocess_utils import communicate_with_timeout


async def run_ffuf(base_url, wordlist=DIRLIST_PATH, threads=40, timeout=8, recursion=3, progress=None):
    def _log(msg):
        if progress:
            progress(msg)
        else:
            print(msg)

    if not base_url:
        return []
    if not os.path.isfile(wordlist):
        _log(f"[!] ffuf wordlist not found: {wordlist}")
        return []

    if not (shutil.which(FFUF_BIN) or shutil.which(FFUF_BIN.split("/")[-1])):
        _log(f"[!] ffuf not found ({FFUF_BIN}) — skipping dir fuzz")
        return []

    proc = await asyncio.create_subprocess_exec(
        FFUF_BIN,
        "-w", wordlist,
        "-u", f"{base_url.rstrip('/')}/FUZZ",
        "-mc", "200,302",
        "-ac",
        "-t", str(threads),
        "-timeout", str(timeout),
        "-recursion",
        "-recursion-depth", str(recursion),
        "-json",
        "-s",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        start_new_session=True,
    )
    try:
        stdout, stderr = await communicate_with_timeout(proc, FFUF_TIMEOUT)
    except TimeoutError as e:
        raise RuntimeError(f"ffuf timeout on {base_url}: {e}") from e

    if proc.returncode != 0:
        
        err = stderr.decode(errors="replace").strip()[:300]
        raise RuntimeError(f"ffuf exit {proc.returncode}: {err}")

    hits = set()
    
    for line in stdout.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            u = data.get("url")
            if u:
                hits.add(u)
        except json.JSONDecodeError:
            if line.startswith("http"):
                hits.add(line)
    return sorted(hits)