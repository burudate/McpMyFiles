"""Thin ctypes wrappers around Windows APIs: file owner, alternate data streams, Restart Manager."""

from __future__ import annotations

import ctypes
from ctypes import wintypes

_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_rstrtmgr = ctypes.WinDLL("rstrtmgr", use_last_error=True)

_PVOID = ctypes.c_void_p
_PPVOID = ctypes.POINTER(ctypes.c_void_p)

# --------------------------------------------------------------------------- owner

SE_FILE_OBJECT = 1
OWNER_SECURITY_INFORMATION = 0x1

_advapi32.GetNamedSecurityInfoW.argtypes = [
    wintypes.LPCWSTR, ctypes.c_int, wintypes.DWORD, _PPVOID, _PPVOID, _PPVOID, _PPVOID, _PPVOID,
]
_advapi32.GetNamedSecurityInfoW.restype = wintypes.DWORD
_advapi32.LookupAccountSidW.argtypes = [
    wintypes.LPCWSTR, _PVOID, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD),
    wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD), ctypes.POINTER(ctypes.c_int),
]
_advapi32.LookupAccountSidW.restype = wintypes.BOOL
_advapi32.ConvertSidToStringSidW.argtypes = [_PVOID, _PPVOID]
_advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL
_kernel32.LocalFree.argtypes = [_PVOID]
_kernel32.LocalFree.restype = _PVOID


def get_owner(path: str) -> dict:
    """Return {"account": "DOMAIN\\user", "sid": "S-1-..."} for the owner of a file or directory."""
    psid = _PVOID()
    psd = _PVOID()
    rc = _advapi32.GetNamedSecurityInfoW(
        path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, ctypes.byref(psid), None, None, None, ctypes.byref(psd)
    )
    if rc != 0:
        return {"error": f"GetNamedSecurityInfoW failed (win32 error {rc})"}
    try:
        sid_str = None
        buf = _PVOID()
        if _advapi32.ConvertSidToStringSidW(psid, ctypes.byref(buf)):
            sid_str = ctypes.wstring_at(buf.value)
            _kernel32.LocalFree(buf)

        name = ctypes.create_unicode_buffer(256)
        domain = ctypes.create_unicode_buffer(256)
        cch_name = wintypes.DWORD(256)
        cch_domain = wintypes.DWORD(256)
        sid_use = ctypes.c_int()
        account = None
        if _advapi32.LookupAccountSidW(
            None, psid, name, ctypes.byref(cch_name), domain, ctypes.byref(cch_domain), ctypes.byref(sid_use)
        ):
            account = f"{domain.value}\\{name.value}" if domain.value else name.value
        return {"account": account, "sid": sid_str}
    finally:
        _kernel32.LocalFree(psd)


# --------------------------------------------------------------------------- alternate data streams

class _WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [("StreamSize", ctypes.c_longlong), ("cStreamName", ctypes.c_wchar * 296)]


_INVALID_HANDLE = ctypes.c_void_p(-1).value

_kernel32.FindFirstStreamW.argtypes = [wintypes.LPCWSTR, ctypes.c_int, _PVOID, wintypes.DWORD]
_kernel32.FindFirstStreamW.restype = wintypes.HANDLE
_kernel32.FindNextStreamW.argtypes = [wintypes.HANDLE, _PVOID]
_kernel32.FindNextStreamW.restype = wintypes.BOOL
_kernel32.FindClose.argtypes = [wintypes.HANDLE]
_kernel32.FindClose.restype = wintypes.BOOL


def list_alternate_streams(path: str) -> list[dict]:
    """List NTFS alternate data streams (e.g. Zone.Identifier) — excludes the unnamed main stream."""
    data = _WIN32_FIND_STREAM_DATA()
    handle = _kernel32.FindFirstStreamW(path, 0, ctypes.byref(data), 0)
    if handle in (None, _INVALID_HANDLE):
        return []
    streams = []
    try:
        while True:
            raw = data.cStreamName  # e.g. ":Zone.Identifier:$DATA"
            if raw != "::$DATA":
                name = raw[1:].rsplit(":", 1)[0] if raw.startswith(":") else raw
                streams.append({"name": name, "size": data.StreamSize})
            if not _kernel32.FindNextStreamW(handle, ctypes.byref(data)):
                break
    finally:
        _kernel32.FindClose(handle)
    return streams


# --------------------------------------------------------------------------- Restart Manager

class _RM_UNIQUE_PROCESS(ctypes.Structure):
    _fields_ = [("dwProcessId", wintypes.DWORD), ("ProcessStartTime", wintypes.FILETIME)]


class _RM_PROCESS_INFO(ctypes.Structure):
    _fields_ = [
        ("Process", _RM_UNIQUE_PROCESS),
        ("strAppName", ctypes.c_wchar * 256),
        ("strServiceShortName", ctypes.c_wchar * 64),
        ("ApplicationType", ctypes.c_int),
        ("AppStatus", ctypes.c_ulong),
        ("TSSessionId", wintypes.DWORD),
        ("bRestartable", wintypes.BOOL),
    ]


_rstrtmgr.RmStartSession.argtypes = [ctypes.POINTER(wintypes.DWORD), wintypes.DWORD, ctypes.c_wchar_p]
_rstrtmgr.RmStartSession.restype = wintypes.DWORD
_rstrtmgr.RmRegisterResources.argtypes = [
    wintypes.DWORD, wintypes.UINT, ctypes.POINTER(wintypes.LPCWSTR), wintypes.UINT, _PVOID, wintypes.UINT, _PVOID,
]
_rstrtmgr.RmRegisterResources.restype = wintypes.DWORD
_rstrtmgr.RmGetList.argtypes = [
    wintypes.DWORD, ctypes.POINTER(wintypes.UINT), ctypes.POINTER(wintypes.UINT),
    ctypes.POINTER(_RM_PROCESS_INFO), ctypes.POINTER(wintypes.DWORD),
]
_rstrtmgr.RmGetList.restype = wintypes.DWORD
_rstrtmgr.RmEndSession.argtypes = [wintypes.DWORD]
_rstrtmgr.RmEndSession.restype = wintypes.DWORD

_ERROR_MORE_DATA = 234
_RM_APP_TYPES = {0: "unknown", 1: "main_window", 2: "other_window", 3: "service", 4: "explorer", 5: "console", 1000: "critical"}


def processes_using_file(path: str) -> list[dict]:
    """Return processes that currently hold the file open (via the Restart Manager API)."""
    session = wintypes.DWORD()
    key = ctypes.create_unicode_buffer(33)
    rc = _rstrtmgr.RmStartSession(ctypes.byref(session), 0, key)
    if rc != 0:
        raise OSError(f"RmStartSession failed (win32 error {rc})")
    try:
        files = (wintypes.LPCWSTR * 1)(path)
        rc = _rstrtmgr.RmRegisterResources(session, 1, files, 0, None, 0, None)
        if rc != 0:
            raise OSError(f"RmRegisterResources failed (win32 error {rc})")

        needed = wintypes.UINT(0)
        count = wintypes.UINT(0)
        reason = wintypes.DWORD()
        arr = None
        for _ in range(5):
            rc = _rstrtmgr.RmGetList(session, ctypes.byref(needed), ctypes.byref(count), arr, ctypes.byref(reason))
            if rc == 0:
                break
            if rc != _ERROR_MORE_DATA:
                raise OSError(f"RmGetList failed (win32 error {rc})")
            arr = (_RM_PROCESS_INFO * needed.value)()
            count = wintypes.UINT(needed.value)
        else:
            raise OSError("RmGetList: process list kept changing")

        result = []
        for i in range(count.value if arr is not None else 0):
            info = arr[i]
            result.append({
                "pid": info.Process.dwProcessId,
                "app_name": info.strAppName,
                "service_name": info.strServiceShortName or None,
                "app_type": _RM_APP_TYPES.get(info.ApplicationType, str(info.ApplicationType)),
                "session_id": info.TSSessionId,
            })
        return result
    finally:
        _rstrtmgr.RmEndSession(session)
