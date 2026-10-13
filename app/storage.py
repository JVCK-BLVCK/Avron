"Storage logic for scan results (Save/load)"
import asyncio
import json 
import logging
import threading

from app.config import settings
from pathlib import Path


logger = logging.getLogger(__name__)

# Make sure the SCAN_DIR exists and is writable.  
# This is done at module load time so that any issues are caught early, rather than at runtime when a scan is being saved.

_DEFAULT_SCAN_DIR = Path(__file__).parent.parent /"scans"

# SCAN_DIR = Path(settings.scan_dir)
# # Validate that the scan_dir is indeed a valid path
# if not SCAN_DIR.is_absolute():
#     raise ValueError(f"SCAN_DIR must be an absolute path not {SCAN_DIR}")

# # Check if the directory exists, and create it if it does not
# if not SCAN_DIR.exists():
#     os.makedirs(SCAN_DIR, exist_ok=True)
SCAN_DIR = (
    Path(settings.scan_dir)
    if settings.scan_dir
    else _DEFAULT_SCAN_DIR

)

SCAN_DIR.mkdir(parents=True, exist_ok=True)


# Constants to tag lines in JSONL for easier parsing- This allows us to store metadata and results in the same file without confusion
_TYPE_METADATA = "metadata"
_TYPE_RESULT = "result"

# threading.lock (NOT asyncio.lock) -writes run in background threads, not on the event loop.
# asyncio.lock would deadlock when acquired from a thread; threading.lock is safe from both threads and async code 
_write_lock = threading.Lock()

# ____Write___

def save_scan_sync(scan_id: str, data: dict) -> None:
    """
         Synchronous, atomic, thread-safe write.
 
    Why synchronous?
        run_nuclei runs inside asyncio.to_thread().  Calling asyncio.run()
        from that thread (to invoke the async save_scan) creates a second event
        loop.  On Windows, aiofiles in the second loop opens the file with a
        write handle that Windows treats as exclusive, blocking any concurrent
        aiofiles.open(..., "r") on the main loop — indefinite deadlock.
        Plain file I/O has no such interaction with the event loop.
 
    Why atomic (write-to-tmp + rename)?
        save_scan previously opened with mode "w" (truncate).  If load_scan
        read between the truncation and the completed write it got an empty or
        partial file and raised JSONDecodeError.  Writing to a .tmp file first
        and atomically replacing the destination means readers always see a
        complete snapshot.
 
        os.replace() is atomic on POSIX.  On Windows (Python ≥ 3.4) Python
        opens files with FILE_SHARE_DELETE, so os.replace() succeeds even when
        a reader has the destination open — the reader keeps its handle to the
        old data; the new file immediately takes the name.
    """
    path = SCAN_DIR / f"{scan_id}.jsonl"
    tmp = path.with_suffix(".tmp")

    lines: list[str] = [
        json.dumps({
            "_type": _TYPE_METADATA,
            "scan_id":   data.get("scan_id"),
            "target":    data.get("target"),
            "status":    data.get("status"),
            "timestamp": data.get("timestamp"),
            "error":     data.get("error"),
        })
    ]
    for item in data.get("results", []):
        lines.append(json.dumps({"_type": _TYPE_RESULT, **item}))

    content = "\n".join(lines) + "\n"

    try:
        with _write_lock:
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(path)  # atomic overwrite — safe even if path is open
    except (OSError, PermissionError) as e:
        raise IOError(f"Failed to save scan{scan_id}: {str(e)}")

async def save_scan(scan_id: str, data: dict) -> None:
    """
        Async wrapper around save_scan_sync for use on the event loop
        (e.g. the initial write in scan_target).
    
        Delegates to save_scan_sync via asyncio.to_thread so it doesn't block
        the event loop while holding _write_lock.
    """
    await asyncio.to_thread(save_scan_sync, scan_id, data)


# ___Read___Path___

async def load_scan(scan_id: str) -> dict | None:
    """

        Load scan data from disk.
    
        Uses synchronous path.read_text() instead of aiofiles.  aiofiles keeps
        the file handle open across await points, which on Windows can collide with
        a concurrent save_scan_sync rename and raise PermissionError.
        read_text() opens, reads, and closes the file in one OS call, minimising
        the window during which the handle is held.
    
        A small retry loop handles the rare race where the atomic rename makes the
        file transiently unavailable.
    
        Per-line JSONDecodeError handling means a single corrupt line (e.g. from an
        unexpected process kill mid-write) doesn't discard all results.

    """
    path = SCAN_DIR / f"{scan_id}.jsonl"
    if not path.exists():
        return None
 
    content: str | None = None
    for attempt in range (3):
        try:
            content = path.read_text(encoding="utf-8")
            break 
        except (PermissionError, OSError):
            if attempt == 2:
                raise IOError (f"Failed to read scan {scan_id} after 3 attempts")
            await asyncio.sleep(0.05)   # yield briefly; let the rename finish

    if content is None:
        return None
    
    results: list = []
    metadata: dict | None = None

    for raw in content.splitlines():
        raw = raw.strip()
        if not raw:
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            raise IOError(f"Failed to load scan {scan_id}: {str(e)}")

        t = obj.get("_type")
        if t == _TYPE_METADATA:
            metadata = obj
        elif t == _TYPE_RESULT:
            results.append({k: v for k, v in obj.items() if k != "_type"})

    if metadata is None:
        return
    
    return {
        "scan_id":   metadata.get("scan_id"),
        "target":    metadata.get("target"),
        "status":    metadata.get("status"),
        "timestamp": metadata.get("timestamp"),
        "error":     metadata.get("error"),
        "results":   results,
    }
