"""Read the NTFS USN change journal.

As administrator: FSCTL_READ_USN_JOURNAL on the raw volume (file names included).
Otherwise: FSCTL_READ_UNPRIVILEGED_USN_JOURNAL (Win10 1709+), where file names are omitted —
names can then only be recovered for files that still exist, via their file reference number.

The journal records every create / write / rename / delete on the volume (typically the last few days,
~32 MB), including files that no longer exist. It does NOT record which process made the change.
"""

from __future__ import annotations

import ctypes
import struct
from ctypes import wintypes
from collections.abc import Iterator

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel32.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
_kernel32.CreateFileW.restype = wintypes.HANDLE
_kernel32.DeviceIoControl.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p,
]
_kernel32.DeviceIoControl.restype = wintypes.BOOL
_kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel32.CloseHandle.restype = wintypes.BOOL
_kernel32.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
_kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD


class _FILE_ID_DESCRIPTOR(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("Type", ctypes.c_int), ("FileId", ctypes.c_byte * 16)]


_kernel32.OpenFileById.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(_FILE_ID_DESCRIPTOR), wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
]
_kernel32.OpenFileById.restype = wintypes.HANDLE

_INVALID_HANDLE = ctypes.c_void_p(-1).value
_FSCTL_QUERY_USN_JOURNAL = 0x000900F4
_FSCTL_READ_UNPRIVILEGED_USN_JOURNAL = 0x000903AB
_FSCTL_READ_USN_JOURNAL = 0x000900BB
_GENERIC_READ = 0x80000000
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_FILE_SHARE_ALL = 0x7
_OPEN_EXISTING = 3
_FILE_READ_ATTRIBUTES = 0x80
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_EPOCH_AS_FILETIME = 116444736000000000

REASONS = {
    0x00000001: "data_overwrite",
    0x00000002: "data_extend",
    0x00000004: "data_truncation",
    0x00000010: "stream_overwrite",
    0x00000020: "stream_extend",
    0x00000040: "stream_truncation",
    0x00000100: "create",
    0x00000200: "delete",
    0x00000400: "ea_change",
    0x00000800: "security_change",
    0x00001000: "rename_old_name",
    0x00002000: "rename_new_name",
    0x00004000: "indexable_change",
    0x00008000: "basic_info_change",
    0x00010000: "hard_link_change",
    0x00020000: "compression_change",
    0x00040000: "encryption_change",
    0x00080000: "object_id_change",
    0x00100000: "reparse_point_change",
    0x00200000: "stream_change",
    0x80000000: "close",
}
CREATE = 0x100
DELETE = 0x200


def reason_names(mask: int) -> list[str]:
    return [name for bit, name in REASONS.items() if mask & bit]


class Journal:
    """Handle on a volume's USN journal. Use as a context manager."""

    def __init__(self, drive: str = "C:"):
        root = drive.rstrip("\\/") + "\\"
        self.drive = root[:2].upper()
        # Opening the raw volume for reading only succeeds as administrator; it yields file names.
        self._vol = _kernel32.CreateFileW(
            "\\\\.\\" + self.drive, _GENERIC_READ, _FILE_SHARE_ALL, None, _OPEN_EXISTING, 0, None
        )
        self.privileged = self._vol not in (None, _INVALID_HANDLE)
        self._h = _kernel32.CreateFileW(
            root, _FILE_READ_ATTRIBUTES, _FILE_SHARE_ALL, None, _OPEN_EXISTING, _FILE_FLAG_BACKUP_SEMANTICS, None
        )
        if self._h in (None, _INVALID_HANDLE):
            raise OSError(f"cannot open {root} (win32 error {ctypes.get_last_error()})")
        buf = ctypes.create_string_buffer(80)
        n = wintypes.DWORD()
        if not _kernel32.DeviceIoControl(self._h, _FSCTL_QUERY_USN_JOURNAL, None, 0, buf, 80, ctypes.byref(n), None):
            err = ctypes.get_last_error()
            self.close()
            raise OSError(f"FSCTL_QUERY_USN_JOURNAL failed (win32 error {err}); the volume may have no USN journal")
        self.journal_id, self.first_usn, self.next_usn = struct.unpack_from("<Qqq", buf.raw)
        self._path_cache: dict[int, str | None] = {}

    def __enter__(self) -> "Journal":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        for attr in ("_h", "_vol"):
            h = getattr(self, attr, None)
            if h not in (None, _INVALID_HANDLE):
                _kernel32.CloseHandle(h)
            setattr(self, attr, None)

    def records(self) -> Iterator[dict]:
        """Yield every record from the oldest retained one to the newest."""
        out = ctypes.create_string_buffer(1 << 20)
        n = wintypes.DWORD()
        usn = self.first_usn
        while True:
            inp = struct.pack("<qIIQQQ", usn, 0xFFFFFFFF, 0, 0, 0, self.journal_id)
            if self.privileged:
                handle, code = self._vol, _FSCTL_READ_USN_JOURNAL
            else:
                handle, code = self._h, _FSCTL_READ_UNPRIVILEGED_USN_JOURNAL
            if not _kernel32.DeviceIoControl(handle, code, inp, len(inp), out, len(out), ctypes.byref(n), None):
                raise OSError(f"reading the USN journal failed (win32 error {ctypes.get_last_error()})")
            if n.value <= 8:
                return
            raw = out.raw[: n.value]
            next_usn = struct.unpack_from("<q", raw)[0]
            off = 8
            while off < len(raw):
                length, major = struct.unpack_from("<IH", raw, off)
                if length == 0:
                    break
                if major == 2:
                    frn, parent, rec_usn, ts, reason, _src, _sec, attrs, name_len, name_off = struct.unpack_from(
                        "<QQqqIIIIHH", raw, off + 8
                    )
                elif major == 3:
                    frn_lo, frn_hi, par_lo, par_hi, rec_usn, ts, reason, _src, _sec, attrs, name_len, name_off = (
                        struct.unpack_from("<QQQQqqIIIIHH", raw, off + 8)
                    )
                    frn, parent = frn_lo | (frn_hi << 64), par_lo | (par_hi << 64)
                else:
                    off += length
                    continue
                name = raw[off + name_off: off + name_off + name_len].decode("utf-16-le", errors="replace")
                yield {
                    "frn": frn,
                    "parent_frn": parent,
                    "usn": rec_usn,
                    "time": (ts - _EPOCH_AS_FILETIME) / 1e7,
                    "reason": reason,
                    "attributes": attrs,
                    "is_dir": bool(attrs & _FILE_ATTRIBUTE_DIRECTORY),
                    "name": name,
                }
                off += length
            if next_usn == usn:
                return
            usn = next_usn

    def path_of(self, frn: int) -> str | None:
        """Current full path of an existing file/directory by its file reference number (None if gone)."""
        if frn in self._path_cache:
            return self._path_cache[frn]
        desc = _FILE_ID_DESCRIPTOR()
        desc.dwSize = ctypes.sizeof(desc)
        desc.Type = 0 if frn < (1 << 64) else 2  # FileIdType / ExtendedFileIdType
        ctypes.memmove(desc.FileId, frn.to_bytes(16, "little"), 16)
        path = None
        h = _kernel32.OpenFileById(self._h, ctypes.byref(desc), 0, _FILE_SHARE_ALL, None, _FILE_FLAG_BACKUP_SEMANTICS)
        if h not in (None, _INVALID_HANDLE):
            try:
                buf = ctypes.create_unicode_buffer(1024)
                if _kernel32.GetFinalPathNameByHandleW(h, buf, 1024, 0):
                    path = buf.value.removeprefix("\\\\?\\")
            finally:
                _kernel32.CloseHandle(h)
        self._path_cache[frn] = path
        return path
