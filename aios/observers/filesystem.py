"""Filesystem observers — mount table, stat, and scoped read.

Read paths are the highest-risk surface in the whole project: process metadata
is T0, but file *contents* are arbitrary attacker-controlled bytes. The read
observer therefore always returns content wrapped as T4 external data, and
never interprets what it read.
"""

from __future__ import annotations

import os
import stat as stat_module
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from aios.observers.paths import PathEscapeError, read_text, resolve_under

#: FUSE/network filesystems are refused for reading by default: their content
#: is served by something outside the kernel and may be attacker-controlled in
#: ways a local stat cannot reveal.
BLOCKED_FS_TYPES = frozenset(
    {
        "fuseblk",
        "fuse.sshfs",
        "fuse.rclone",
        "nfs",
        "nfs4",
        "cifs",
        "smbfs",
        "9p",
        "afs",
        "ceph",
        "glusterfs",
        "beegfs",
    }
)

#: Paths with no business being read through a natural-language interface.
#: Checked after realpath resolution, so symlinks cannot dodge this.
SENSITIVE_PREFIXES = (
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh",
    "/root",
    "/proc/kcore",
    "/dev/mem",
    "/dev/kmem",
    "/dev/port",
    "/sys/kernel/security",
    "/boot",
)


class FilesystemEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    mount_point: str
    fs_type: str
    options: list[str] = Field(default_factory=list)
    total_bytes: int | None = None
    used_bytes: int | None = None
    free_bytes: int | None = None
    used_percent: float | None = None
    inodes_total: int | None = None
    inodes_used: int | None = None


class FilesystemList(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mounts: list[FilesystemEntry]
    total: int


class PathMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str
    exists: bool
    is_dir: bool = False
    is_file: bool = False
    is_symlink: bool = False
    size_bytes: int | None = None
    mode: str | None = None
    owner_uid: int | None = None
    owner_gid: int | None = None
    modified_utc: str | None = None
    accessed_utc: str | None = None
    inode: int | None = None
    nlink: int | None = None


def parse_mounts(text: str, fstypes: set[str] | None = None) -> list[FilesystemEntry]:
    """Parse /proc/mounts. Octal escapes in mount points are decoded.

    Duplicated mount points are collapsed (later entries win) so a bind mount
    cannot present a second, friendlier view of the same path.
    """
    by_point: dict[str, FilesystemEntry] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        device, mount_point, fs_type, options = parts[0], parts[1], parts[2], parts[3]
        if fstypes and fs_type not in fstypes:
            continue
        mount_point = _unescape(mount_point)
        by_point[mount_point] = FilesystemEntry(
            name=device,
            mount_point=mount_point,
            fs_type=fs_type,
            options=options.split(","),
        )

    entries = list(by_point.values())
    for entry in entries:
        try:
            usage = os.statvfs(entry.mount_point)
        except OSError:
            continue
        block = usage.f_frsize
        total = usage.f_blocks * block
        free = usage.f_bavail * block
        used = total - usage.f_bfree * block
        entry.total_bytes = total
        entry.free_bytes = free
        entry.used_bytes = used
        entry.used_percent = round(100.0 * used / (used + free), 2) if (used + free) else 0.0
        entry.inodes_total = usage.f_files
        entry.inodes_used = usage.f_files - usage.f_ffree
    return entries


def _unescape(value: str) -> str:
    out: list[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\" and i + 3 < len(value) and all(c in "01234567" for c in value[i + 1 : i + 4]):
            out.append(chr(int(value[i + 1 : i + 4], 8)))
            i += 4
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def list_mounts(
    proc_root: Path, fstypes: set[str] | None = None, pseudo: bool = False
) -> FilesystemList:
    text = read_text(resolve_under(Path(proc_root), "mounts"))
    if not pseudo:
        fstypes = (fstypes or set()) | {
            "ext2", "ext3", "ext4", "btrfs", "xfs", "f2fs", "vfat", "exfat",
            "ntfs", "ntfs3", "zfs", "overlay", "bcachefs", "reiserfs", "jfs",
        }
    entries = parse_mounts(text, fstypes)
    return FilesystemList(mounts=entries, total=len(entries))


def stat_path(path: str | Path) -> PathMetadata:
    """stat a path, following symlinks (stat semantics, not lstat)."""
    p = Path(path)
    try:
        st = p.stat()
    except (OSError, ValueError):
        return PathMetadata(path=str(p), exists=False)

    return PathMetadata(
        path=str(p),
        exists=True,
        is_dir=stat_module.S_ISDIR(st.st_mode),
        is_file=stat_module.S_ISREG(st.st_mode),
        is_symlink=p.is_symlink(),
        size_bytes=st.st_size,
        mode=stat_module.filemode(st.st_mode),
        owner_uid=st.st_uid,
        owner_gid=st.st_gid,
        modified_utc=datetime.fromtimestamp(st.st_mtime, tz=UTC).isoformat(),
        accessed_utc=datetime.fromtimestamp(st.st_atime, tz=UTC).isoformat(),
        inode=st.st_ino,
        nlink=st.st_nlink,
    )


def is_sensitive(path: str | Path) -> bool:
    """True if the resolved path is in a never-read list."""
    try:
        resolved = str(Path(path).resolve())
    except (OSError, ValueError):
        resolved = str(path)
    for prefix in SENSITIVE_PREFIXES:
        if resolved == prefix or resolved.startswith(prefix.rstrip("/") + "/"):
            return True
    return False


def check_readable(path: str | Path) -> str | None:
    """Return a reason string if the path must not be read, else None."""
    p = Path(path)
    if is_sensitive(p):
        return f"path matches sensitive prefix: {p}"
    if not p.exists():
        return f"path does not exist: {p}"
    if p.is_dir():
        return f"path is a directory, use filesystem.list: {p}"
    try:
        st = p.stat()
    except OSError as exc:
        return f"cannot stat {p}: {exc}"
    if not stat_module.S_ISREG(st.st_mode):
        return f"not a regular file: {p}"
    # A filesystem that can serve attacker-chosen bytes is refused.
    try:
        dev = st.st_dev
        fstype = _fstype_for_device(dev)
    except OSError:
        fstype = None
    if fstype and fstype in BLOCKED_FS_TYPES:
        return f"filesystem type {fstype} is not readable through AIOS: {p}"
    return None


def _fstype_for_device(device: int) -> str | None:
    mountinfo = Path("/proc/self/mountinfo").read_text(encoding="utf-8", errors="replace")
    for line in mountinfo.splitlines():
        parts = line.split(" - ")
        if len(parts) != 2:
            continue
        left, right = parts[0].split(), parts[1].split()
        if not left:
            continue
        try:
            if int(left[2], 16) == device:
                return right[0]
        except (ValueError, IndexError):
            continue
    return None


def list_directory(
    path: str | Path, max_entries: int = 500, show_hidden: bool = False
) -> list[PathMetadata]:
    """List a directory as metadata only — names, never contents."""
    p = Path(path)
    if not p.is_dir():
        raise NotADirectoryError(f"not a directory: {p}")
    out: list[PathMetadata] = []
    with os.scandir(p) as it:
        for index, entry in enumerate(it):
            if index >= max_entries:
                break
            if not show_hidden and entry.name.startswith("."):
                continue
            try:
                st = entry.stat(follow_symlinks=False)
            except OSError:
                out.append(PathMetadata(path=str(p / entry.name), exists=False))
                continue

            out.append(
                PathMetadata(
                    path=str(p / entry.name),
                    exists=True,
                    is_dir=stat_module.S_ISDIR(st.st_mode),
                    is_file=stat_module.S_ISREG(st.st_mode),
                    is_symlink=stat_module.S_ISLNK(st.st_mode),
                    size_bytes=st.st_size,
                    mode=stat_module.filemode(st.st_mode),
                    owner_uid=st.st_uid,
                    owner_gid=st.st_gid,
                    modified_utc=datetime.fromtimestamp(st.st_mtime, tz=UTC).isoformat(),
                    inode=st.st_ino,
                    nlink=st.st_nlink,
                )
            )
    return out


def read_file(path: str | Path, max_bytes: int = 1_048_576) -> str:
    """Read a file as UTF-8 with replacement, after policy checks.

    Caller must run :func:`check_readable` first — this returns the content,
    and content is data, not authority, regardless of who asked.
    """
    return read_text(Path(path), max_bytes=max_bytes)


__all__ = [
    "BLOCKED_FS_TYPES",
    "FilesystemEntry",
    "FilesystemList",
    "PathEscapeError",
    "PathMetadata",
    "SENSITIVE_PREFIXES",
    "check_readable",
    "is_sensitive",
    "list_directory",
    "list_mounts",
    "parse_mounts",
    "read_file",
    "stat_path",
]
