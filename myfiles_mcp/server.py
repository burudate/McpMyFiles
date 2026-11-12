"""MCP server: investigate when / by whom / why local files (especially temp files) were created.

All tools are read-only.
"""

from __future__ import annotations

import fnmatch
import hashlib
import os
import re
import stat as stat_mod
import tempfile
import time
from datetime import datetime
from typing import Literal

import psutil
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from myfiles_mcp import heuristics, powershell, usn, winapi

mcp = MCPServer(
    "myfiles",
    instructions=(
        "Read-only tools for investigating when, by whom and why local files (especially in temp directories) "
        "were created. Typical flow: summarize_temp_activity / find_recent_files -> inspect_file -> "
        "find_processes_using_file / find_processes_started_near / search_file_events -> preview_file."
    ),
)
_RO = ToolAnnotations(readOnlyHint=True, openWorldHint=False)

MAX_SCAN_ENTRIES = 300_000
HASH_SIZE_LIMIT = 200 * 1024 * 1024

_ATTR_FLAGS = {
    stat_mod.FILE_ATTRIBUTE_READONLY: "readonly",
    stat_mod.FILE_ATTRIBUTE_HIDDEN: "hidden",
    stat_mod.FILE_ATTRIBUTE_SYSTEM: "system",
    stat_mod.FILE_ATTRIBUTE_DIRECTORY: "directory",
    stat_mod.FILE_ATTRIBUTE_ARCHIVE: "archive",
    stat_mod.FILE_ATTRIBUTE_TEMPORARY: "temporary",
    stat_mod.FILE_ATTRIBUTE_SPARSE_FILE: "sparse",
    stat_mod.FILE_ATTRIBUTE_REPARSE_POINT: "reparse_point",
    stat_mod.FILE_ATTRIBUTE_COMPRESSED: "compressed",
    stat_mod.FILE_ATTRIBUTE_OFFLINE: "offline",
    stat_mod.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: "not_content_indexed",
    stat_mod.FILE_ATTRIBUTE_ENCRYPTED: "encrypted",
}
_PE_LIKE_EXT = {".exe", ".dll", ".sys", ".msi", ".ps1", ".psm1", ".cat", ".cab", ".vbs", ".js", ".ocx", ".scr"}


# --------------------------------------------------------------------------- helpers

def _iso(ts: float | None) -> str | None:
    if ts is None:
        return None
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


def _parse_time(value: str) -> float:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.astimezone()  # interpret naive input as local time
    return dt.timestamp()


def _norm(path: str) -> str:
    return os.path.abspath(os.path.expandvars(os.path.expanduser(path)))


def _birthtime(st: os.stat_result) -> float:
    return getattr(st, "st_birthtime", st.st_ctime)


def _attrs(st: os.stat_result) -> list[str]:
    value = getattr(st, "st_file_attributes", 0)
    return [name for flag, name in _ATTR_FLAGS.items() if value & flag]


def _temp_roots() -> list[dict]:
    env = os.environ
    local = env.get("LOCALAPPDATA", "")
    sysroot = env.get("SystemRoot", r"C:\Windows")
    candidates = [
        ("python tempfile.gettempdir()", tempfile.gettempdir()),
        ("%TEMP%", env.get("TEMP")),
        ("%TMP%", env.get("TMP")),
        ("%LOCALAPPDATA%\\Temp", os.path.join(local, "Temp") if local else None),
        ("LocalLow\\Temp", os.path.join(env.get("USERPROFILE", ""), "AppData", "LocalLow", "Temp")),
        ("%SystemRoot%\\Temp", os.path.join(sysroot, "Temp")),
        ("%SystemRoot%\\SystemTemp (SYSTEM processes, Win11)", os.path.join(sysroot, "SystemTemp")),
    ]
    seen: dict[str, dict] = {}
    for label, path in candidates:
        if not path:
            continue
        key = os.path.normcase(os.path.realpath(path))
        if key in seen:
            seen[key]["labels"].append(label)
            continue
        exists = os.path.isdir(path)
        readable = False
        if exists:
            try:
                with os.scandir(path) as it:
                    next(it, None)
                readable = True
            except OSError:
                pass
        seen[key] = {"path": os.path.realpath(path), "labels": [label], "exists": exists, "readable": readable}
    return list(seen.values())


def _root_of(path: str, roots: list[str]) -> str | None:
    p = os.path.normcase(path)
    for r in roots:
        rn = os.path.normcase(r).rstrip("\\") + "\\"
        if p.startswith(rn):
            return r
    return None


def _walk(root: str, recursive: bool, include_dirs: bool, counter: list[int]):
    """Yield (path, stat, is_dir). Does not follow symlinks/junctions. counter[0] tracks scanned entries."""
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            it = os.scandir(current)
        except OSError:
            continue
        with it:
            for entry in it:
                counter[0] += 1
                if counter[0] > MAX_SCAN_ENTRIES:
                    return
                try:
                    st = entry.stat(follow_symlinks=False)
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    continue
                if is_dir:
                    if recursive and not entry.is_junction() and not entry.is_symlink():
                        stack.append(entry.path)
                    if include_dirs:
                        yield entry.path, st, True
                else:
                    yield entry.path, st, False


def _read_zone_identifier(path: str) -> dict | None:
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
            text = f.read(8192)
    except OSError:
        return None
    info: dict = {"raw": text.strip()}
    zones = {"0": "local machine", "1": "intranet", "2": "trusted", "3": "internet", "4": "restricted"}
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            info[k.strip()] = v.strip()
    if "ZoneId" in info:
        info["zone"] = zones.get(info["ZoneId"], info["ZoneId"])
    return info


def _proc_summary(p: psutil.Process) -> dict:
    with p.oneshot():
        d: dict = {"pid": p.pid}
        for key, fn in (
            ("name", p.name), ("exe", p.exe), ("cmdline", p.cmdline), ("username", p.username),
            ("ppid", p.ppid), ("status", p.status),
        ):
            try:
                d[key] = fn()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                d[key] = None
        try:
            d["started"] = _iso(p.create_time())
        except (psutil.AccessDenied, OSError):
            d["started"] = None
    return d


# --------------------------------------------------------------------------- tools

@mcp.tool(annotations=_RO)
def list_temp_directories() -> list[dict]:
    """List the temporary directories on this machine (%TEMP%, C:\\Windows\\Temp, SystemTemp, ...)
    with whether each exists and is readable by this server."""
    return _temp_roots()


@mcp.tool(annotations=_RO)
def find_recent_files(
    directory: str | None = None,
    since_minutes: float = 60,
    name_pattern: str = "*",
    recursive: bool = True,
    include_dirs: bool = False,
    sort_by: Literal["created", "modified"] = "created",
    limit: int = 100,
) -> dict:
    """Find files created (or modified) within the last `since_minutes`, newest first.

    directory: folder to scan. Omit to scan all temp directories.
    name_pattern: glob matched against the file name (e.g. "*.tmp", "_MEI*").
    sort_by: "created" uses the NTFS creation time; "modified" uses last write time.
    Each result includes an `origin_guess` from well-known naming conventions.
    """
    roots = [_norm(directory)] if directory else [r["path"] for r in _temp_roots() if r["readable"]]
    cutoff = time.time() - since_minutes * 60
    counter = [0]
    hits = []
    for root in roots:
        for path, st, is_dir in _walk(root, recursive, include_dirs, counter):
            ts = _birthtime(st) if sort_by == "created" else st.st_mtime
            if ts < cutoff or not fnmatch.fnmatch(os.path.basename(path).lower(), name_pattern.lower()):
                continue
            hits.append((ts, path, st, is_dir, root))
    hits.sort(key=lambda h: h[0], reverse=True)

    files = []
    for ts, path, st, is_dir, root in hits[:limit]:
        guess = heuristics.guess_origin(path, root)
        files.append({
            "path": path,
            "is_dir": is_dir,
            "created": _iso(_birthtime(st)),
            "modified": _iso(st.st_mtime),
            "size": None if is_dir else st.st_size,
            "origin_guess": guess[0]["origin"] if guess else None,
        })
    return {
        "scanned_roots": roots,
        "scanned_entries": counter[0],
        "scan_truncated": counter[0] > MAX_SCAN_ENTRIES,
        "total_matches": len(hits),
        "returned": len(files),
        "files": files,
    }


@mcp.tool(annotations=_RO)
def summarize_temp_activity(since_hours: float = 24, directory: str | None = None, top: int = 40) -> dict:
    """Aggregate recently created files by their top-level entry under each temp directory,
    to see which programs are producing the most temp files. Omit `directory` to use all temp dirs."""
    roots = [_norm(directory)] if directory else [r["path"] for r in _temp_roots() if r["readable"]]
    cutoff = time.time() - since_hours * 3600
    counter = [0]
    groups: dict[tuple[str, str], dict] = {}
    for root in roots:
        for path, st, _ in _walk(root, True, False, counter):
            created = _birthtime(st)
            if created < cutoff:
                continue
            rel = os.path.relpath(path, root)
            top_entry = rel.split(os.sep, 1)[0]
            g = groups.setdefault((root, top_entry), {
                "root": root, "entry": top_entry, "is_dir": os.sep in rel,
                "count": 0, "total_bytes": 0, "first": created, "last": created, "samples": [],
            })
            g["count"] += 1
            g["total_bytes"] += st.st_size
            g["first"] = min(g["first"], created)
            g["last"] = max(g["last"], created)
            if len(g["samples"]) < 3:
                g["samples"].append(rel)

    ordered = sorted(groups.values(), key=lambda g: g["count"], reverse=True)[:top]
    for g in ordered:
        guess = heuristics.guess_origin(os.path.join(g["root"], g["entry"]), g["root"])
        g["origin_guess"] = guess[0]["origin"] if guess else None
        g["first"], g["last"] = _iso(g["first"]), _iso(g["last"])
    return {
        "since": _iso(cutoff),
        "scanned_entries": counter[0],
        "scan_truncated": counter[0] > MAX_SCAN_ENTRIES,
        "groups": ordered,
    }


@mcp.tool(annotations=_RO)
def inspect_file(path: str, compute_hash: bool = True, sibling_window_seconds: float = 10) -> dict:
    """Collect everything that hints at when / who / why a file was created:
    timestamps, attributes, owner account, alternate data streams (Zone.Identifier = download source URL),
    detected file type, PE version info & code signature, SHA-256, name-based origin guesses,
    the parent folder's owner/creation time, and other files created in the same folder at about the same time."""
    path = _norm(path)
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError as e:
        return {"path": path, "error": str(e)}
    is_dir = stat_mod.S_ISDIR(st.st_mode)
    created = _birthtime(st)

    roots = [r["path"] for r in _temp_roots()]
    temp_root = _root_of(path, roots)
    info: dict = {
        "path": path,
        "is_dir": is_dir,
        "size": None if is_dir else st.st_size,
        "created": _iso(created),
        "modified": _iso(st.st_mtime),
        "accessed": _iso(st.st_atime),
        "attributes": _attrs(st),
        "owner": winapi.get_owner(path),
        "in_temp_directory": temp_root,
        "origin_guesses": heuristics.guess_origin(path, temp_root),
    }
    if st.st_mtime < created - 2:
        info["note_timestamps"] = (
            "modified < created: the file was probably copied or extracted from an archive/installer "
            "that preserved the original write time."
        )

    streams = winapi.list_alternate_streams(path)
    info["alternate_streams"] = streams
    if any(s["name"].lower() == "zone.identifier" for s in streams):
        info["zone_identifier"] = _read_zone_identifier(path)

    if not is_dir:
        head = b""
        try:
            with open(path, "rb") as f:
                head = f.read(4096)
        except OSError as e:
            info["read_error"] = str(e)
        info["detected_type"] = heuristics.detect_type(head) if head or not info.get("read_error") else None

        ext = os.path.splitext(path)[1].lower()
        if head.startswith(b"MZ") or ext in _PE_LIKE_EXT:
            try:
                info["pe_and_signature"] = powershell.run_json(
                    powershell.PE_INFO_SCRIPT, {"MF_PATH": path}, timeout=30
                )
            except Exception as e:  # noqa: BLE001 - report, don't fail the whole inspection
                info["pe_and_signature"] = {"error": str(e)}

        if compute_hash and "read_error" not in info:
            if st.st_size <= HASH_SIZE_LIMIT:
                h = hashlib.sha256()
                try:
                    with open(path, "rb") as f:
                        for chunk in iter(lambda: f.read(1024 * 1024), b""):
                            h.update(chunk)
                    info["sha256"] = h.hexdigest()
                except OSError as e:
                    info["sha256_error"] = str(e)
            else:
                info["sha256"] = f"skipped (> {HASH_SIZE_LIMIT // (1024 * 1024)} MB)"

    parent = os.path.dirname(path)
    try:
        pst = os.stat(parent)
        info["parent_directory"] = {
            "path": parent,
            "created": _iso(_birthtime(pst)),
            "owner": winapi.get_owner(parent),
        }
    except OSError:
        pass

    siblings = []
    try:
        with os.scandir(parent) as it:
            for entry in it:
                if os.path.normcase(entry.path) == os.path.normcase(path):
                    continue
                try:
                    est = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                delta = _birthtime(est) - created
                if abs(delta) <= sibling_window_seconds:
                    siblings.append({"name": entry.name, "created_delta_seconds": round(delta, 3)})
    except OSError:
        pass
    siblings.sort(key=lambda s: abs(s["created_delta_seconds"]))
    info["created_around_same_time_in_folder"] = siblings[:30]

    # For a folder, its executables usually reveal the product that extracted it.
    products = []
    if is_dir:
        try:
            with os.scandir(path) as it:
                children = sorted(e.name for e in it)
        except OSError:
            children = []
        info["contents_sample"] = children[:40]
        exes = [c for c in children if c.lower().endswith(".exe")][:3]
        for name in exes:
            try:
                pe = powershell.run_json(powershell.PE_INFO_SCRIPT, {"MF_PATH": os.path.join(path, name)}, timeout=30)
            except Exception:  # noqa: BLE001
                continue
            products.append({"name": name, **pe})
        info["executables"] = products
    elif isinstance(info.get("pe_and_signature"), dict) and "error" not in info["pe_and_signature"]:
        products.append({"name": os.path.basename(path), **info["pe_and_signature"]})

    info["web_search_queries"] = heuristics.web_search_queries(path, temp_root, info["origin_guesses"], products)
    return info


@mcp.tool(annotations=_RO)
def preview_file(
    path: str,
    mode: Literal["auto", "text", "hex", "strings"] = "auto",
    max_bytes: int = 4096,
) -> dict:
    """Read the beginning of a file to learn why it exists (log headers, embedded app names, paths...).

    mode "auto": text if it looks textual, otherwise hex.
    mode "strings": extract printable ASCII / UTF-16 strings from the first 1 MB (like `strings`), useful for binaries.
    """
    path = _norm(path)
    max_bytes = max(1, min(max_bytes, 64 * 1024))
    try:
        with open(path, "rb") as f:
            data = f.read(1024 * 1024 if mode == "strings" else max_bytes)
    except OSError as e:
        return {"path": path, "error": str(e)}

    if mode == "strings":
        found: list[str] = []
        for m in re.finditer(rb"[\x20-\x7e]{6,}", data):
            found.append(m.group().decode("ascii"))
        for m in re.finditer(rb"(?:[\x20-\x7e]\x00){6,}", data):
            found.append(m.group().decode("utf-16-le"))
        # Drop machine-code noise: keep strings that are mostly letters/digits/spaces/path punctuation.
        def readable(s: str) -> bool:
            good = sum(1 for ch in s if ch.isalnum() or ch in " ._-:/\\")
            return good / len(s) >= 0.85 and sum(ch.isalpha() for ch in s) >= 4

        unique = [s for s in dict.fromkeys(found) if readable(s)]
        # Paths, URLs and file names are the most telling — list them first.
        interesting = re.compile(r"[\\/]|https?:|\.(exe|dll|log|tmp|json|xml|ini|dat)\b", re.IGNORECASE)
        unique.sort(key=lambda s: 0 if interesting.search(s) else 1)
        return {"path": path, "mode": "strings", "count": len(unique), "strings": unique[:500]}

    if mode == "text" or (mode == "auto" and (heuristics.looks_textual(data) or data[:2] in (b"\xff\xfe", b"\xfe\xff"))):
        if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
            text = data.decode("utf-16", errors="replace")
        else:
            try:
                text = data.decode("utf-8-sig")
            except UnicodeDecodeError:
                text = data.decode("cp932", errors="replace")
        return {"path": path, "mode": "text", "bytes_read": len(data), "text": text}

    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hexpart:<47}  {asc}")
    return {"path": path, "mode": "hex", "bytes_read": len(data), "hex": "\n".join(lines)}


@mcp.tool(annotations=_RO)
def find_processes_using_file(path: str) -> dict:
    """Which running processes currently have this file open (Windows Restart Manager).
    Works without admin rights. Only shows processes holding the file *right now*."""
    path = _norm(path)
    try:
        procs = winapi.processes_using_file(path)
    except OSError as e:
        return {"path": path, "error": str(e)}
    for p in procs:
        try:
            p.update({k: v for k, v in _proc_summary(psutil.Process(p["pid"])).items() if k != "pid"})
        except psutil.Error:
            pass
    return {"path": path, "processes": procs}


@mcp.tool(annotations=_RO)
def find_processes_started_near(
    time_iso: str | None = None,
    path: str | None = None,
    before_seconds: float = 300,
    after_seconds: float = 30,
) -> dict:
    """List *currently running* processes whose start time is close to a given moment,
    as candidates for the creator of a file. Give either `time_iso` (e.g. "2026-09-29T14:03:00")
    or `path` (its creation time is used). Processes that already exited are not visible —
    use search_file_events for historical data."""
    if path:
        try:
            target = _birthtime(os.stat(_norm(path)))
        except OSError as e:
            return {"error": str(e)}
    elif time_iso:
        target = _parse_time(time_iso)
    else:
        return {"error": "specify time_iso or path"}

    result = []
    for p in psutil.process_iter():
        try:
            ct = p.create_time()
        except psutil.Error:
            continue
        if target - before_seconds <= ct <= target + after_seconds:
            try:
                d = _proc_summary(p)
            except psutil.Error:
                continue
            d["started_offset_seconds"] = round(ct - target, 1)
            result.append(d)
    result.sort(key=lambda d: abs(d["started_offset_seconds"]))
    return {"target_time": _iso(target), "processes": result}


@mcp.tool(annotations=_RO)
def get_process_info(pid: int) -> dict:
    """Details of a running process: exe, command line, user, working directory, start time,
    the parent chain (who launched it) and its children."""
    try:
        p = psutil.Process(pid)
        info = _proc_summary(p)
    except psutil.Error as e:
        return {"pid": pid, "error": str(e)}
    try:
        info["cwd"] = p.cwd()
    except psutil.Error:
        info["cwd"] = None

    chain = []
    try:
        for parent in p.parents()[:10]:
            try:
                chain.append(_proc_summary(parent))
            except psutil.Error:
                chain.append({"pid": parent.pid})
    except psutil.Error:
        pass
    info["parent_chain"] = chain

    children = []
    try:
        for c in p.children()[:30]:
            try:
                children.append({"pid": c.pid, "name": c.name()})
            except psutil.Error:
                pass
    except psutil.Error:
        pass
    info["children"] = children
    return info


@mcp.tool(annotations=_RO)
def search_file_events(
    name_contains: str,
    since_hours: float = 24,
    max_results: int = 50,
    include_security_log: bool = True,
) -> dict:
    """Search Windows event logs for file create/delete records whose path contains `name_contains`.
    This is the only way to reliably know WHICH PROCESS created a file, including processes that already exited.

    Sources:
      - Sysmon (Event 11 FileCreate, 23/26 FileDelete). Also resolves the creating process's command line
        and parent process from Sysmon Event 1. Requires Sysmon to be installed.
      - Security log (Event 4663/4656 object access). Requires "Audit File System" + a SACL on the folder.
    Reading these logs usually requires running the MCP server as administrator.
    A status of log_not_found / access_denied / no_events explains why nothing was returned.
    """
    if not name_contains.strip():
        return {"error": "name_contains must not be empty"}
    try:
        data = powershell.run_json(
            powershell.EVENT_SEARCH_SCRIPT,
            {
                "MF_NEEDLE": name_contains,
                "MF_HOURS": str(since_hours),
                "MF_MAX": str(max_results),
                "MF_SECURITY": "1" if include_security_log else "0",
            },
            timeout=180,
        )
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)}

    hints = []
    if data.get("sysmon", {}).get("status") == "log_not_found":
        hints.append("Sysmon is not installed. See README 'Sysmon の導入' to record file creation with the creating process.")
    if "access_denied" in (data.get("sysmon", {}).get("status"), data.get("security", {}).get("status")):
        hints.append("Run the MCP client (and thus this server) as administrator to read these logs.")
    if hints:
        data["hints"] = hints
    return data


@mcp.tool(annotations=_RO)
def search_usn_journal(
    name_contains: str | None = None,
    path_contains: str | None = None,
    since_hours: float = 24,
    drive: str = "C:",
    only_create_delete: bool = True,
    max_files: int = 100,
) -> dict:
    """Search the NTFS change journal (USN) for file activity — INCLUDING FILES THAT WERE ALREADY DELETED.
    Shows each file's create time, delete time, lifetime and change types.
    Works without admin rights, but then names of already-deleted files are unavailable (their folder,
    times and counts still are); as admin every file name is available.

    name_contains: substring of the file name (case-insensitive).
    path_contains: substring of the full path, e.g. "\\AppData\\Local\\Temp\\".
    only_create_delete: keep only files that were created or deleted in the window (skip mere modifications).
    The journal usually covers the last few days; `journal_oldest_record` tells the exact coverage.
    It does not record the process — combine with search_file_events / find_processes_started_near.
    """
    cutoff = time.time() - since_hours * 3600
    needle = name_contains.casefold() if name_contains else None
    path_needle = path_contains.casefold() if path_contains else None

    try:
        journal = usn.Journal(drive)
    except OSError as e:
        return {"error": str(e)}
    with journal:
        dir_map: dict[int, tuple[str, int]] = {}
        files: dict[int, dict] = {}
        oldest = None
        try:
            for rec in journal.records():
                if oldest is None:
                    oldest = rec["time"]
                if rec["is_dir"]:
                    dir_map[rec["frn"]] = (rec["name"], rec["parent_frn"])
                if rec["time"] < cutoff:
                    continue
                # Without admin rights names are empty; those records are name-filtered later.
                if needle and rec["name"] and needle not in rec["name"].casefold():
                    continue
                f = files.get(rec["frn"])
                if f is None:
                    f = files[rec["frn"]] = {
                        "names": [], "parent_frn": rec["parent_frn"], "is_dir": rec["is_dir"],
                        "first": rec["time"], "last": rec["time"], "created": None, "deleted": None, "mask": 0,
                    }
                if rec["name"] not in f["names"]:
                    f["names"].append(rec["name"])
                f["parent_frn"] = rec["parent_frn"]
                f["last"] = rec["time"]
                f["mask"] |= rec["reason"]
                if rec["reason"] & usn.CREATE and f["created"] is None:
                    f["created"] = rec["time"]
                if rec["reason"] & usn.DELETE:
                    f["deleted"] = rec["time"]
        except OSError as e:
            return {"error": str(e)}

        def resolve_dir(frn: int, depth: int = 0) -> str:
            path = journal.path_of(frn)
            if path:
                return path
            if frn in dir_map and dir_map[frn][0] and depth < 40:
                name, parent = dir_map[frn]
                return resolve_dir(parent, depth + 1) + "\\" + name
            return f"<deleted dir #{frn & 0xFFFFFFFFFFFF}>"

        results = []
        unnamed_skipped = 0
        for frn, f in files.items():
            if only_create_delete and not (f["mask"] & (usn.CREATE | usn.DELETE)):
                continue
            directory = resolve_dir(f["parent_frn"])
            if path_needle and path_needle not in (directory + "\\").casefold():
                # The file name may still complete the match, but only if we know it.
                if not f["names"][-1] or path_needle not in (directory + "\\" + f["names"][-1]).casefold():
                    continue
            name = f["names"][-1] or None
            if name is None and f["deleted"] is None:
                current = journal.path_of(frn)  # unprivileged mode: recover the name of a surviving file
                if current:
                    directory, name = os.path.dirname(current), os.path.basename(current)
            if needle and (name is None or needle not in name.casefold()):
                unnamed_skipped += name is None
                continue
            results.append((f, directory, name))

    results.sort(key=lambda r: r[0]["first"], reverse=True)
    by_dir: dict[str, int] = {}
    for _, directory, _ in results:
        by_dir[directory] = by_dir.get(directory, 0) + 1
    out = []
    for f, directory, name in results[:max_files]:
        lifetime = None
        if f["created"] is not None and f["deleted"] is not None:
            lifetime = round(f["deleted"] - f["created"], 3)
        out.append({
            "path": directory + "\\" + (name or "<name unavailable: deleted file, run as admin for names>"),
            "is_dir": f["is_dir"],
            "former_names": [n for n in f["names"][:-1] if n] or None,
            "created": _iso(f["created"]),
            "deleted": _iso(f["deleted"]),
            "lifetime_seconds": lifetime,
            "first_seen": _iso(f["first"]),
            "last_seen": _iso(f["last"]),
            "changes": [r for r in usn.reason_names(f["mask"]) if r != "close"],
        })
    return {
        "drive": journal.drive,
        "mode": "admin (all file names)" if journal.privileged
        else "unprivileged (names only for files that still exist; deleted files show their folder only)",
        "unnamed_deleted_files_skipped_by_name_filter": unnamed_skipped if needle else None,
        "journal_oldest_record": _iso(oldest),
        "since": _iso(cutoff),
        "total_matches": len(results),
        "created_count": sum(1 for f, _, _ in results if f["created"] is not None),
        "deleted_count": sum(1 for f, _, _ in results if f["deleted"] is not None),
        "top_directories": sorted(by_dir.items(), key=lambda kv: kv[1], reverse=True)[:20],
        "returned": len(out),
        "files": out,
    }


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
