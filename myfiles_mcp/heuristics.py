"""Heuristics for guessing which program produced a file, from its name/path and leading bytes."""

from __future__ import annotations

import re
from pathlib import PureWindowsPath

# (regex matched against each path component, likely origin, note)
# These are well-known naming conventions; a match is a hint, not proof.
_NAME_PATTERNS: list[tuple[str, str, str]] = [
    (r"^_MEI[0-9A-Za-z_]+$", "PyInstaller", "Onefile PyInstaller apps extract themselves here on each launch"),
    (r"^onefile_\d+_\d+$", "Nuitka", "Nuitka onefile extraction directory"),
    (r"^\.net$", ".NET single-file app", "Self-extracting .NET single-file bundles"),
    (r"^scoped_dir\d+_\d+$", "Chromium-based app (Chrome/Edge/Electron)", "Chromium scoped temp dir"),
    (r"^chrome_(drag|url_fetcher|BITS|Unpacker)", "Google Chrome", ""),
    (r"^msedge_", "Microsoft Edge", ""),
    (r"^puppeteer_dev_(chrome_)?profile-", "Puppeteer", "Headless browser automation profile"),
    (r"^playwright", "Playwright", "Browser automation"),
    (r"^mozilla-temp-", "Firefox / Thunderbird", ""),
    (r"^~DF[0-9A-F]+\.TMP$", "OLE / Microsoft Office", "OLE structured storage temp file"),
    (r"^~\$", "Microsoft Office", "Owner/lock file of an open document"),
    (r"^msohtmlclip", "Microsoft Office", "Clipboard HTML fragments"),
    (r"^CVR[0-9A-F]+\.tmp", "Microsoft Office / Outlook", ""),
    (r"^Outlook Logging$", "Microsoft Outlook", ""),
    (r"^tmp[0-9A-F]{1,4}\.tmp$", ".NET Path.GetTempFileName()", "Any .NET program"),
    (r"^tmp[a-z0-9_]{8}(\..+)?$", "Python tempfile module", "Any Python program (incl. pip, build tools)"),
    (r"^[a-z0-9]{8}\.[a-z0-9]{3}$", ".NET Path.GetRandomFileName()", "Any .NET program (installers/updaters often extract here)"),
    (r"^python-languageserver-cancellation$", "VS Code Python extension (Pylance)", ""),
    (r"^pip-", "pip", "pip build/unpack/install directories"),
    (r"^(npm-|npm_cache|\.npm)", "npm", ""),
    (r"^node-compile-cache$", "Node.js", "V8 compile cache"),
    (r"^(vscode-|VSCode|vscode_)", "Visual Studio Code", ""),
    (r"^go-build\d+$", "Go toolchain", ""),
    (r"^hsperfdata_", "Java (JVM)", "JVM performance data"),
    (r"^(jar_cache|\+~JF)", "Java", ""),
    (r"^etilqs_", "SQLite", "SQLite temp file ('sqlite' reversed)"),
    (r"^is-[A-Z0-9]{5}\.tmp$", "Inno Setup installer", ""),
    (r"^ns[a-zA-Z0-9]{3,5}\.tmp$", "NSIS installer", ""),
    (r"^~nsu", "NSIS uninstaller", ""),
    (r"^Rar\$", "WinRAR", "Files opened directly from an archive"),
    (r"^7z[A-Z0-9]+", "7-Zip", "Files opened directly from an archive"),
    (r"^Temp\d+_.+\.zip$", "Windows Explorer (zip)", "File opened directly from a zip"),
    (r"^Cab[A-Z0-9]+\.tmp$", "Windows cabinet extraction", ""),
    (r"^MSI[a-z0-9]+\.LOG$", "Windows Installer (msiexec)", ""),
    (r"^dd_.*\.log$", "Visual Studio Installer", ""),
    (r"^WinGet$", "WinGet", ""),
    (r"^__PSScriptPolicyTest_", "PowerShell", "Execution policy / AppLocker probe"),
    (r"^Diagnostics$|^DiagOutputDir$", "Windows diagnostics", ""),
    (r"^\{[0-9A-Fa-f-]{36}\}$", "Installer / updater (GUID-named)", "Often MSI, Windows Update, or app updaters"),
    (r"^claude", "Claude Code / Claude app", ""),
    (r"^(AdobeARM|acrobat_sbx|Adobe)", "Adobe", ""),
    (r"^Zoom", "Zoom", ""),
    (r"^(Teams|MSTeams)", "Microsoft Teams", ""),
    (r"^OneDrive", "OneDrive", ""),
    (r"^gen_py$", "pywin32", "COM type library cache"),
    (r"^Crashpad$|\.dmp$", "Crash dump", "Crashpad / Windows Error Reporting"),
    (r"^WER[0-9A-F]+\.tmp", "Windows Error Reporting", ""),
]
_COMPILED = [(re.compile(p, re.IGNORECASE), origin, note) for p, origin, note in _NAME_PATTERNS]


def guess_origin(path: str, root: str | None = None) -> list[dict]:
    """Match each component of `path` (below `root`, if given) against known naming patterns."""
    parts = PureWindowsPath(path).parts
    if root:
        root_parts = PureWindowsPath(root).parts
        if [p.lower() for p in parts[: len(root_parts)]] == [p.lower() for p in root_parts]:
            parts = parts[len(root_parts):]
    hits = []
    for part in parts:
        for rx, origin, note in _COMPILED:
            if rx.search(part):
                hits.append({"component": part, "origin": origin, "note": note})
                break
    return hits


# --------------------------------------------------------------------------- web search hints

_RANDOM_NAME = re.compile(r"^[a-z0-9]{8}\.[a-z0-9]{3}$", re.IGNORECASE)
_VARIABLE_PART = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f-]{27}\}?|[0-9a-f]{8,}|\d{3,}", re.IGNORECASE)


def generalize_name(name: str) -> str:
    """Replace random / numeric parts (GUIDs, hashes, counters) with '*' so the name can be searched on the web."""
    if _RANDOM_NAME.match(name):
        return "*"
    return _VARIABLE_PART.sub("*", name)


def _searchable(term: str) -> bool:
    return bool(re.search(r"[A-Za-z]{3,}", term))


def web_search_queries(
    path: str, root: str | None, origins: list[dict], products: list[dict]
) -> list[str]:
    """Suggest web search queries that are likely to explain what created the file."""
    parts = list(PureWindowsPath(path).parts)
    if root:
        root_len = len(PureWindowsPath(root).parts)
        if [p.lower() for p in parts[:root_len]] == [p.lower() for p in PureWindowsPath(root).parts]:
            parts = parts[root_len:]
    location = "%TEMP%" if root else ""
    queries: list[str] = []
    for p in products:
        label = " ".join(dict.fromkeys(v for v in (p.get("company"), p.get("product"), p.get("description")) if v))
        if label:
            queries.append(f"{label} {p.get('name', '')} temp folder".strip())
    for o in origins:
        queries.append(f"{o['origin']} {generalize_name(o['component'])} temp files")
    for part in parts[:2] + parts[-1:]:
        g = generalize_name(part)
        if _searchable(g):
            queries.append(f'"{g}" {location} what creates'.strip())
    return list(dict.fromkeys(queries))[:6]


# --------------------------------------------------------------------------- file type by magic bytes

_MAGIC: list[tuple[bytes, str]] = [
    (b"MZ", "PE executable (exe/dll/sys)"),
    (b"PK\x03\x04", "ZIP container (zip/docx/xlsx/jar/nupkg/vsix...)"),
    (b"%PDF", "PDF"),
    (b"\x89PNG", "PNG image"),
    (b"GIF8", "GIF image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"RIFF", "RIFF (wav/avi/webp)"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound file (msi/doc/xls/msg)"),
    (b"7z\xbc\xaf\x27\x1c", "7z archive"),
    (b"Rar!", "RAR archive"),
    (b"MSCF", "Microsoft Cabinet"),
    (b"\x1f\x8b", "gzip"),
    (b"{\\rtf", "RTF"),
    (b"\x7fELF", "ELF executable"),
    (b"regf", "Windows registry hive"),
    (b"ElfFile", "Windows event log (evtx)"),
    (b"MDMP", "Minidump (crash dump)"),
    (b"L\x00\x00\x00\x01\x14\x02\x00", "Windows shortcut (lnk)"),
    (b"\xef\xbb\xbf", "UTF-8 text (BOM)"),
    (b"\xff\xfe", "UTF-16LE text (BOM)"),
    (b"<?xml", "XML"),
]


def detect_type(head: bytes) -> str:
    if not head:
        return "empty"
    for magic, label in _MAGIC:
        if head.startswith(magic):
            return label
    stripped = head.lstrip()
    if stripped[:1] in (b"{", b"["):
        return "probably JSON / text"
    if looks_textual(head):
        return "text"
    return "unknown binary"


def looks_textual(data: bytes) -> bool:
    if not data:
        return True
    if b"\x00" in data[:1024]:
        return False
    printable = sum(1 for b in data if b in (9, 10, 13) or 32 <= b < 127 or b >= 0x80)
    return printable / len(data) > 0.95
