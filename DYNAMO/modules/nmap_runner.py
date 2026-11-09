import asyncio
import os
import shutil
import tempfile

from config.tools import NMAP_BIN, NMAP_TIMEOUT, NMAP_PORTS
from modules._subprocess_utils import communicate_with_timeout


async def run_nmap(target, save_dir=None, scan_id=None):
    fd, temp_xml = tempfile.mkstemp(suffix=".xml")
    os.close(fd)
    fd, temp_txt = tempfile.mkstemp(suffix=".txt")
    os.close(fd)

    try:
        try:
            process = await asyncio.create_subprocess_exec(
                NMAP_BIN,
                "-Pn",
                "-sV",
                "-p", NMAP_PORTS,
                "-T4",
                "-oX", temp_xml,
                "-oN", temp_txt,
                target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
            stdout, stderr = await communicate_with_timeout(
                process, NMAP_TIMEOUT)
        except FileNotFoundError as e:
            raise RuntimeError(f"Could not execute nmap at '{NMAP_BIN}'") from e
        except TimeoutError as e:
            raise RuntimeError(f"nmap timeout on {target}: {e}") from e

        if process.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise RuntimeError(f"Nmap exit {process.returncode}: {err}")

        if not os.path.exists(temp_xml):
            raise RuntimeError("Nmap produced no XML output")

        with open(temp_xml, "r") as f:
            xml_data = f.read()

        if not xml_data.strip():
            raise RuntimeError("Nmap returned empty XML")

        if save_dir:
            safe_target = target.replace("/", "_").replace(":", "_")
            if not safe_target or safe_target in (".", ".."):
                safe_target = "unknown"
            os.makedirs(save_dir, exist_ok=True)

            dest = os.path.join(save_dir, f"{safe_target}.txt")
            shutil.copy(temp_txt, dest)

            if scan_id is not None:
                archived = os.path.join(
                    save_dir, f"{safe_target}_scan{scan_id}.txt"
                )
                shutil.copy(temp_txt, archived)
            

        return xml_data
    finally:
        for p in (temp_xml, temp_txt):
            if os.path.exists(p):
                os.remove(p)