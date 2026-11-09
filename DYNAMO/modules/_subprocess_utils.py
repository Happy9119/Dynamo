import asyncio
import os
import signal


def _kill_tree(proc, sig):
    try:
        pgid = os.getpgid(proc.pid)
        if pgid != os.getpgid(0):
            os.killpg(pgid, sig)
            return True
    except (ProcessLookupError, PermissionError, OSError):
        pass

    try:
        proc.send_signal(sig)
        return True
    except (ProcessLookupError, OSError):
        return False


async def communicate_with_timeout(proc, timeout_sec):
    try:
        return await asyncio.wait_for(proc.communicate(), timeout=timeout_sec)
    except asyncio.TimeoutError:
        _kill_tree(proc, signal.SIGTERM)
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            _kill_tree(proc, signal.SIGKILL)
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
        raise TimeoutError(f"subprocess exceeded {timeout_sec}s and was terminated")