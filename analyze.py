"""Interactive disk and folder storage analyzer with read-only cleanup advisor.

Displays occupied and free space for every available drive, lets the user
inspect accurate on-disk folder sizes recursively (handling Windows cloud/virtual
files, compressed files, and junctions properly), and suggests useless or
reclaimable items at the end of every drive/folder result without ever deleting
anything automatically.
"""

from __future__ import annotations

import ctypes
import os
import queue
import shutil
import stat
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Reparse point tags used on Windows for directory junctions and symlinks.
IO_REPARSE_TAG_MOUNT_POINT = getattr(stat, "IO_REPARSE_TAG_MOUNT_POINT", 0xA0000003)
IO_REPARSE_TAG_SYMLINK = getattr(stat, "IO_REPARSE_TAG_SYMLINK", 0xA000000C)
LINK_REPARSE_TAGS = (IO_REPARSE_TAG_MOUNT_POINT, IO_REPARSE_TAG_SYMLINK)

# Windows file attribute flags for cloud placeholders, compression, and sparse files.
FILE_ATTRIBUTE_SPARSE_FILE = 0x200
FILE_ATTRIBUTE_COMPRESSED = 0x800
FILE_ATTRIBUTE_OFFLINE = 0x1000
FILE_ATTRIBUTE_RECALL_ON_OPEN = 0x40000
FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS = 0x400000

CLOUD_ONLY_ATTRS = (
    FILE_ATTRIBUTE_OFFLINE
    | FILE_ATTRIBUTE_RECALL_ON_OPEN
    | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS
)
COMPRESSED_OR_SPARSE_ATTRS = FILE_ATTRIBUTE_SPARSE_FILE | FILE_ATTRIBUTE_COMPRESSED

DEFAULT_PAGE_SIZE = 25
DEFAULT_SUGGESTION_LIMIT = 6
MAX_SCAN_WORKERS = min(16, max(8, (os.cpu_count() or 4) * 2))

MIN_GENERAL_JUNK_FILE_BYTES = 100 * 1024  # 100 KB for temp/log/dump files
MIN_INSTALLER_FILE_BYTES = 10 * 1024 * 1024  # 10 MB for installers/archives
MIN_DOWNLOADS_ARCHIVE_BYTES = 1 * 1024 * 1024  # 1 MB inside Downloads

if os.name == "nt":
    _kernel32 = ctypes.windll.kernel32
    _GetCompressedFileSizeW = _kernel32.GetCompressedFileSizeW
    _GetCompressedFileSizeW.argtypes = [
        ctypes.c_wchar_p,
        ctypes.POINTER(ctypes.c_uint32),
    ]
    _GetCompressedFileSizeW.restype = ctypes.c_uint32
else:
    _GetCompressedFileSizeW = None

SAFE_JUNK_EXACT_SUFFIXES: tuple[tuple[str, str], ...] = (
    (os.sep + os.path.join("windows", "temp"), "Windows temporary files"),
    (
        os.sep + os.path.join("windows", "softwaredistribution", "download"),
        "Windows Update download cache",
    ),
    (os.sep + os.path.join("windows", "minidump"), "Windows crash minidumps"),
    (os.sep + os.path.join("windows", "livekernelreports"), "Windows kernel crash dumps"),
    (
        os.sep + os.path.join("programdata", "microsoft", "windows", "wer"),
        "Windows Error Reporting dumps/logs",
    ),
    (os.sep + os.path.join("appdata", "local", "temp"), "User temporary files"),
    (os.sep + os.path.join("appdata", "local", "crashdumps"), "Application crash dumps"),
    (os.sep + os.path.join("appdata", "local", "pip", "cache"), "Python pip download cache"),
    (os.sep + os.path.join("appdata", "local", "npm-cache"), "npm package cache"),
    (os.sep + os.path.join("appdata", "roaming", "npm-cache"), "npm package cache"),
    (os.sep + os.path.join("appdata", "local", "nuget", "v3-cache"), "NuGet package cache"),
    (os.sep + os.path.join(".gradle", "caches"), "Gradle build & dependency cache"),
    (os.sep + os.path.join(".next", "cache"), "Next.js compiler cache"),
    (os.sep + os.path.join("node_modules", ".cache"), "Node build tool cache"),
)

SAFE_CACHE_DIR_NAMES: dict[str, str] = {
    "__pycache__": "Python bytecode cache (auto-regenerated)",
    ".pytest_cache": "Pytest cache (auto-regenerated)",
    ".mypy_cache": "Mypy type-check cache (auto-regenerated)",
    ".ruff_cache": "Ruff linter cache (auto-regenerated)",
    ".parcel-cache": "Parcel bundler cache (auto-regenerated)",
    ".sass-cache": "Sass compiler cache (auto-regenerated)",
    "$recycle.bin": "Recycle Bin files (empty via Windows Recycle Bin)",
    "onedrivetemp": "OneDrive temporary staging folder",
    ".cache": "Application/tool cache directory",
}

APPDATA_CACHE_DIR_NAMES: dict[str, str] = {
    "cache": "Application/browser cache (auto-recreated)",
    "cache2": "Browser cache (auto-recreated)",
    "code cache": "Browser JS/Wasm code cache (auto-recreated)",
    "gpucache": "GPU shader cache (auto-recreated)",
    "dawncache": "Browser WebGPU shader cache (auto-recreated)",
    "shadercache": "Graphics shader cache (auto-recreated)",
    "grshadercache": "Graphics shader cache (auto-recreated)",
    "crashpad": "Application crash reports",
    "dxcache": "DirectX shader cache (auto-recreated)",
    "glcache": "OpenGL shader cache (auto-recreated)",
    "_cacache": "npm content-addressable cache",
    "go-build": "Go compiler build cache (auto-recreated)",
}

EXTRA_SAFE_SUFFIXES: tuple[tuple[str, str], ...] = (
    (os.sep + os.path.join("go", "pkg", "mod", "cache", "download"), "Go module download cache (re-fetched as needed)"),
    (os.sep + ".wdm", "WebDriverManager cached browser drivers (auto-recreated)"),
)

INSTALLED_OR_SYSTEM_SEGMENTS: tuple[str, ...] = (
    os.sep + "windows" + os.sep,
    os.sep + "program files" + os.sep,
    os.sep + "program files (x86)" + os.sep,
    os.sep + "programdata" + os.sep,
    os.sep + os.path.join("appdata", "local", "programs") + os.sep,
    os.sep + os.path.join("appdata", "local", "android") + os.sep,
    os.sep + os.path.join("appdata", "local", "arduino"),
    os.sep + os.path.join("appdata", "local", "unity") + os.sep,
    os.sep + os.path.join("appdata", "local", "openai") + os.sep,
    os.sep + ".vscode" + os.sep,
    os.sep + ".antigravity" + os.sep,
    os.sep + ".gemini" + os.sep,
)

EXCLUDED_INSTALLER_SEGMENTS: tuple[str, ...] = INSTALLED_OR_SYSTEM_SEGMENTS + (
    os.sep + os.path.join("go", "pkg", "mod") + os.sep,
    os.sep + os.path.join("appdata", "local", "go-build") + os.sep,
    os.sep + ".wdm" + os.sep,
    os.sep + "node_modules" + os.sep,
    os.sep + ".venv" + os.sep,
    os.sep + "venv" + os.sep,
)

INSTALLER_EXE_KEYWORDS: tuple[str, ...] = ("setup", "install", "installer")

REVIEW_DIR_NAMES: dict[str, str] = {
    "node_modules": "JS dependencies (restore anytime with npm install)",
    ".next": "Next.js build output (rebuilt on next build/dev)",
    ".nuxt": "Nuxt build output (regenerated on build)",
    ".venv": "Python virtual environment (recreatable from requirements)",
    "venv": "Python virtual environment (recreatable from requirements)",
    "temp": "Temporary folder (review contents before removing)",
    "tmp": "Temporary folder (review contents before removing)",
}

REVIEW_SUFFIXES: tuple[tuple[str, str], ...] = (
    (os.sep + ".ollama", "Local Ollama AI models (manage with 'ollama rm')"),
    (os.sep + os.path.join(".android", "avd"), "Android Virtual Device emulator images"),
)

SAFE_FILE_EXTENSIONS: dict[str, str] = {
    ".tmp": "Temporary file",
    ".temp": "Temporary file",
    ".dmp": "Crash dump file",
    ".hdmp": "Heap crash dump file",
    ".mdmp": "Minidump crash file",
    ".etl": "Diagnostic trace log",
    ".bak": "Backup copy file",
    ".old": "Old superseded file",
    ".log": "Log file",
}

SAFE_EXACT_FILENAMES: dict[str, str] = {
    "thumbs.db": "Windows thumbnail cache file",
    ".ds_store": "macOS Finder metadata file",
}

REVIEW_INSTALLER_EXTENSIONS: dict[str, str] = {
    ".exe": "Installer executable (delete if setup already completed)",
    ".msi": "Windows installer package (delete if already installed)",
    ".msix": "Windows app package (delete if already installed)",
    ".iso": "Disk image (delete if no longer needed)",
    ".img": "Disk image (delete if no longer needed)",
    ".zip": "Archive file (delete if already extracted/backed up)",
    ".rar": "Archive file (delete if already extracted/backed up)",
    ".7z": "Archive file (delete if already extracted/backed up)",
    ".tar": "Archive file (delete if already extracted/backed up)",
    ".gz": "Compressed archive (delete if already extracted/backed up)",
    ".cab": "Windows cabinet archive/trace file",
}


@dataclass(frozen=True)
class DriveInfo:
    """Storage statistics for a single logical drive or mount point."""

    letter: str
    root: str
    label: str
    total: int
    used: int
    free: int

    @property
    def used_percent(self) -> float:
        return (self.used / self.total * 100.0) if self.total > 0 else 0.0


@dataclass
class DirInfo:
    """Cached on-disk size and hierarchy summary for a scanned directory."""

    path: str
    total_size: int
    direct_file_size: int
    direct_file_count: int
    total_files: int
    total_folders: int
    subdirs: list[str]
    error_count: int
    cloud_size: int = 0
    direct_cloud_size: int = 0


@dataclass(frozen=True)
class CleanupSuggestion:
    """A read-only cleanup recommendation for a folder or file."""

    path: str
    size: int
    category: str  # "Safe" or "Review"
    reason: str
    is_dir: bool


@dataclass
class _RawDir:
    """Intermediate per-directory entry data collected before bottom-up roll-up."""

    direct_file_size: int
    direct_cloud_size: int
    direct_file_count: int
    subdirs: list[str]
    error_count: int


class ScanProgress:
    """Thread-safe progress counter for directory scans."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.dirs = 0
        self.files = 0
        self.bytes_found = 0

    def add(self, dirs: int, files: int, bytes_found: int) -> None:
        with self._lock:
            self.dirs += dirs
            self.files += files
            self.bytes_found += bytes_found

    def snapshot(self) -> tuple[int, int, int]:
        with self._lock:
            return self.dirs, self.files, self.bytes_found


def format_bytes(num_bytes: int) -> str:
    """Format byte count using base-1024 units matching Windows Explorer."""
    size = float(max(0, num_bytes))
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if size < 1024.0 or unit == "PB":
            if unit == "B":
                return f"{int(size)} B"
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def _to_scan_path(path: str) -> str:
    """Add Windows extended-length prefix when path approaches MAX_PATH."""
    if os.name == "nt" and len(path) >= 240 and not path.startswith("\\\\?\\"):
        if path.startswith("\\\\"):
            return "\\\\?\\UNC\\" + path[2:]
        return "\\\\?\\" + path
    return path


def _strip_scan_prefix(path: str) -> str:
    """Remove Windows extended-length prefix for clean cache keys and display."""
    if os.name == "nt":
        if path.startswith("\\\\?\\UNC\\"):
            return "\\\\" + path[8:]
        if path.startswith("\\\\?\\"):
            return path[4:]
    return path


def _normalize_win_root(path: str) -> str:
    if os.name == "nt" and len(path) == 2 and path.endswith(":"):
        return path + "\\"
    return path


def _same_path(path_a: str, path_b: str) -> bool:
    return os.path.normcase(os.path.abspath(path_a)) == os.path.normcase(
        os.path.abspath(path_b)
    )


def _get_windows_volume_label(root: str) -> str:
    """Return the Windows volume label for a drive root, or empty string."""
    if os.name != "nt":
        return ""
    try:
        buf = ctypes.create_unicode_buffer(261)
        ok = ctypes.windll.kernel32.GetVolumeInformationW(
            root, buf, len(buf), None, None, None, None, 0
        )
        return buf.value.strip() if ok else ""
    except OSError:
        return ""


def get_available_drives() -> list[DriveInfo]:
    """Detect all accessible drives and return their occupied/free space."""
    candidates: list[tuple[str, str]] = []
    if os.name == "nt":
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for idx in range(26):
            if bitmask & (1 << idx):
                letter = chr(65 + idx)
                candidates.append((letter, f"{letter}:\\"))
    else:
        candidates.append(("/", "/"))

    drives: list[DriveInfo] = []
    for letter, root in candidates:
        try:
            usage = shutil.disk_usage(root)
        except OSError:
            continue
        if usage.total <= 0:
            continue
        label = _get_windows_volume_label(root)
        drives.append(
            DriveInfo(
                letter=letter,
                root=root,
                label=label,
                total=usage.total,
                used=usage.used,
                free=usage.free,
            )
        )
    return drives


def _is_reparse_link(entry: os.DirEntry[str]) -> tuple[bool, os.stat_result | None]:
    """Check whether a directory entry is a symlink or Windows junction."""
    if entry.is_symlink():
        return True, None
    try:
        st = entry.stat(follow_symlinks=False)
    except OSError:
        return False, None
    tag = getattr(st, "st_reparse_tag", 0)
    if tag in LINK_REPARSE_TAGS:
        return True, st
    return False, st


def _get_file_disk_size(clean_path: str, st: os.stat_result) -> tuple[int, int]:
    """Return (actual_on_disk_bytes, cloud_placeholder_bytes) for a file.

    Cloud-only placeholders (e.g. Windows CrossDevice or OneDrive Online-only)
    report logical sizes in st_size while consuming 0 bytes on the local SSD.
    Compressed and sparse files report allocated disk size via GetCompressedFileSizeW.
    """
    attrs = getattr(st, "st_file_attributes", 0)
    if attrs & CLOUD_ONLY_ATTRS:
        return 0, st.st_size
    if attrs & COMPRESSED_OR_SPARSE_ATTRS and _GetCompressedFileSizeW is not None:
        high = ctypes.c_uint32(0)
        low = _GetCompressedFileSizeW(_to_scan_path(clean_path), ctypes.byref(high))
        if not (low == 0xFFFFFFFF and ctypes.GetLastError() != 0):
            return (high.value << 32) | low, 0
    return st.st_size, 0


def _path_has_segment(lower_path: str, segments: tuple[str, ...]) -> bool:
    """Return True if lower_path matches or sits inside any listed directory segment."""
    padded = lower_path if lower_path.endswith(os.sep) else lower_path + os.sep
    return any(segment in padded for segment in segments)


def _classify_folder_candidate(clean_path: str) -> tuple[str, str] | None:
    """Return (category, reason) if folder matches a known cleanup rule."""
    lower = clean_path.lower().rstrip("\\/")
    base = os.path.basename(lower)

    for suffix, reason in SAFE_JUNK_EXACT_SUFFIXES + EXTRA_SAFE_SUFFIXES:
        if lower.endswith(suffix):
            return "Safe", reason

    if base in SAFE_CACHE_DIR_NAMES:
        return "Safe", SAFE_CACHE_DIR_NAMES[base]

    if (os.sep + "appdata" + os.sep) in lower and base in APPDATA_CACHE_DIR_NAMES:
        return "Safe", APPDATA_CACHE_DIR_NAMES[base]

    if base in REVIEW_DIR_NAMES and not _path_has_segment(lower, INSTALLED_OR_SYSTEM_SEGMENTS):
        return "Review", REVIEW_DIR_NAMES[base]

    for suffix, reason in REVIEW_SUFFIXES:
        if lower.endswith(suffix):
            return "Review", reason

    return None


def _classify_file_candidate(
    clean_path: str, file_name: str, disk_size: int
) -> tuple[str, str] | None:
    """Return (category, reason) if a file is a notable junk or review item."""
    if disk_size <= 0:
        return None

    lower_name = file_name.lower()
    if lower_name in SAFE_EXACT_FILENAMES and disk_size >= 1024:
        return "Safe", SAFE_EXACT_FILENAMES[lower_name]

    _, ext = os.path.splitext(lower_name)
    if ext in SAFE_FILE_EXTENSIONS and disk_size >= MIN_GENERAL_JUNK_FILE_BYTES:
        return "Safe", SAFE_FILE_EXTENSIONS[ext]

    if ext in REVIEW_INSTALLER_EXTENSIONS:
        lower_path = clean_path.lower()
        if _path_has_segment(lower_path, EXCLUDED_INSTALLER_SEGMENTS):
            return None

        in_downloads = (os.sep + "downloads" + os.sep) in lower_path
        if ext == ".exe":
            in_desktop = (os.sep + "desktop" + os.sep) in lower_path
            parent_dir = os.path.dirname(clean_path).rstrip("\\/")
            in_drive_root = len(parent_dir) == 2 and parent_dir.endswith(":")
            has_installer_word = any(kw in lower_name for kw in INSTALLER_EXE_KEYWORDS)
            if not (in_downloads or in_desktop or in_drive_root or has_installer_word):
                return None

        threshold = MIN_DOWNLOADS_ARCHIVE_BYTES if in_downloads else MIN_INSTALLER_FILE_BYTES
        if disk_size >= threshold:
            return "Review", REVIEW_INSTALLER_EXTENSIONS[ext]

    return None


def _scan_dir_for_queue(
    clean_dir: str,
) -> tuple[_RawDir, list[CleanupSuggestion]]:
    """Read immediate entries of clean_dir, computing on-disk file sizes and file candidates."""
    direct_file_size = 0
    direct_cloud_size = 0
    direct_file_count = 0
    subdirs: list[str] = []
    errors = 0
    file_suggestions: list[CleanupSuggestion] = []

    try:
        with os.scandir(_to_scan_path(clean_dir)) as entries:
            for entry in entries:
                try:
                    is_link, st = _is_reparse_link(entry)
                    if is_link:
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        subdirs.append(_strip_scan_prefix(entry.path))
                    else:
                        if st is None:
                            st = entry.stat(follow_symlinks=False)
                        clean_file = _strip_scan_prefix(entry.path)
                        disk_bytes, cloud_bytes = _get_file_disk_size(clean_file, st)
                        direct_file_size += disk_bytes
                        direct_cloud_size += cloud_bytes
                        direct_file_count += 1
                        match = _classify_file_candidate(
                            clean_file, entry.name, disk_bytes
                        )
                        if match is not None:
                            cat, reason = match
                            file_suggestions.append(
                                CleanupSuggestion(
                                    path=clean_file,
                                    size=disk_bytes,
                                    category=cat,
                                    reason=reason,
                                    is_dir=False,
                                )
                            )
                except OSError:
                    errors += 1
    except OSError:
        errors += 1

    raw = _RawDir(
        direct_file_size=direct_file_size,
        direct_cloud_size=direct_cloud_size,
        direct_file_count=direct_file_count,
        subdirs=subdirs,
        error_count=errors,
    )
    return raw, file_suggestions


def _render_progress(root_path: str, progress: ScanProgress, started_at: float) -> None:
    """Print an in-place single-line progress indicator."""
    dirs, files, total_bytes = progress.snapshot()
    elapsed = time.perf_counter() - started_at
    msg = (
        f"\rScanning {root_path} ... "
        f"{dirs:,} folders | {files:,} files | {format_bytes(total_bytes)} "
        f"({elapsed:.1f}s)"
    )
    sys.stdout.write(msg.ljust(78))
    sys.stdout.flush()


def _aggregate_bottom_up(
    root_path: str, raw_dirs: dict[str, _RawDir]
) -> dict[str, DirInfo]:
    """Compute bottom-up DirInfo totals across raw_dirs without recursion."""
    nodes: dict[str, DirInfo] = {}
    stack: list[tuple[str, bool]] = [(root_path, False)]

    while stack:
        current, visited = stack.pop()
        raw = raw_dirs.get(current)
        if raw is None:
            nodes[current] = DirInfo(
                path=current,
                total_size=0,
                direct_file_size=0,
                direct_file_count=0,
                total_files=0,
                total_folders=0,
                subdirs=[],
                error_count=1,
            )
            continue

        if not visited:
            if not raw.subdirs:
                nodes[current] = DirInfo(
                    path=current,
                    total_size=raw.direct_file_size,
                    direct_file_size=raw.direct_file_size,
                    direct_file_count=raw.direct_file_count,
                    total_files=raw.direct_file_count,
                    total_folders=0,
                    subdirs=[],
                    error_count=raw.error_count,
                    cloud_size=raw.direct_cloud_size,
                    direct_cloud_size=raw.direct_cloud_size,
                )
            else:
                stack.append((current, True))
                for child in raw.subdirs:
                    stack.append((child, False))
        else:
            tot_size = raw.direct_file_size
            tot_cloud = raw.direct_cloud_size
            tot_files = raw.direct_file_count
            tot_folders = len(raw.subdirs)
            tot_errs = raw.error_count
            for child in raw.subdirs:
                c_info = nodes[child]
                tot_size += c_info.total_size
                tot_cloud += c_info.cloud_size
                tot_files += c_info.total_files
                tot_folders += c_info.total_folders
                tot_errs += c_info.error_count

            nodes[current] = DirInfo(
                path=current,
                total_size=tot_size,
                direct_file_size=raw.direct_file_size,
                direct_file_count=raw.direct_file_count,
                total_files=tot_files,
                total_folders=tot_folders,
                subdirs=raw.subdirs,
                error_count=tot_errs,
                cloud_size=tot_cloud,
                direct_cloud_size=raw.direct_cloud_size,
            )

    return nodes


def scan_directory_tree(
    root_path: str,
    cache: dict[str, DirInfo],
    cleanup_index: dict[str, CleanupSuggestion],
) -> DirInfo | None:
    """Scan root_path in parallel using work-stealing and populate cache atomically."""
    if root_path in cache:
        return cache[root_path]

    started_at = time.perf_counter()
    progress = ScanProgress()
    stop_event = threading.Event()
    done_event = threading.Event()
    work_queue: queue.Queue[str | None] = queue.Queue()
    work_queue.put(root_path)

    merge_lock = threading.Lock()
    raw_dirs: dict[str, _RawDir] = {}
    all_file_suggestions: list[CleanupSuggestion] = []

    def worker() -> None:
        local_raw: dict[str, _RawDir] = {}
        local_files: list[CleanupSuggestion] = []
        batch_dirs = 0
        batch_files = 0
        batch_bytes = 0

        while True:
            item = work_queue.get()
            if item is None:
                work_queue.task_done()
                break

            try:
                if stop_event.is_set():
                    continue

                local_stack = [item]
                while local_stack and not stop_event.is_set():
                    cur = local_stack.pop()
                    raw, file_cands = _scan_dir_for_queue(cur)
                    local_raw[cur] = raw
                    if file_cands:
                        local_files.extend(file_cands)

                    batch_dirs += 1
                    batch_files += raw.direct_file_count
                    batch_bytes += raw.direct_file_size
                    if batch_dirs >= 100:
                        progress.add(batch_dirs, batch_files, batch_bytes)
                        batch_dirs = batch_files = batch_bytes = 0

                    if raw.subdirs:
                        if work_queue.qsize() < 64:
                            for sub in raw.subdirs[1:]:
                                work_queue.put(sub)
                            local_stack.append(raw.subdirs[0])
                        else:
                            local_stack.extend(raw.subdirs)
            finally:
                work_queue.task_done()

        if batch_dirs or batch_files or batch_bytes:
            progress.add(batch_dirs, batch_files, batch_bytes)

        if not stop_event.is_set():
            with merge_lock:
                raw_dirs.update(local_raw)
                all_file_suggestions.extend(local_files)

    threads = [
        threading.Thread(target=worker, daemon=True) for _ in range(MAX_SCAN_WORKERS)
    ]
    for t in threads:
        t.start()

    def wait_for_queue() -> None:
        work_queue.join()
        done_event.set()

    joiner = threading.Thread(target=wait_for_queue, daemon=True)
    joiner.start()

    _render_progress(root_path, progress, started_at)
    try:
        while not done_event.wait(timeout=0.15):
            _render_progress(root_path, progress, started_at)
    except KeyboardInterrupt:
        stop_event.set()
        while True:
            try:
                queued = work_queue.get_nowait()
                if queued is not None:
                    work_queue.task_done()
            except queue.Empty:
                break
        for _ in threads:
            work_queue.put(None)
        for t in threads:
            t.join(timeout=0.2)
        sys.stdout.write("\r" + " " * 78 + "\r")
        sys.stdout.flush()
        print("Scan cancelled.")
        return None

    for _ in threads:
        work_queue.put(None)
    for t in threads:
        t.join()

    new_nodes = _aggregate_bottom_up(root_path, raw_dirs)

    # Collect matching cleanup directories now that exact folder sizes are aggregated.
    new_suggestions: dict[str, CleanupSuggestion] = {}
    for dir_path, info in new_nodes.items():
        if info.total_size <= 0:
            continue
        match = _classify_folder_candidate(dir_path)
        if match is not None:
            cat, reason = match
            new_suggestions[dir_path] = CleanupSuggestion(
                path=dir_path,
                size=info.total_size,
                category=cat,
                reason=reason,
                is_dir=True,
            )

    for fsug in all_file_suggestions:
        new_suggestions[fsug.path] = fsug

    cache.update(new_nodes)
    cleanup_index.update(new_suggestions)

    root_info = new_nodes[root_path]
    elapsed = time.perf_counter() - started_at
    sys.stdout.write("\r" + " " * 78 + "\r")
    sys.stdout.flush()
    print(
        f"Scan complete in {elapsed:.1f}s: "
        f"{root_info.total_folders + 1:,} folders, {root_info.total_files:,} files."
    )
    return root_info


def list_direct_files(path: str) -> list[tuple[str, int, int]]:
    """Return (filename, on_disk_bytes, cloud_bytes) sorted by on-disk size."""
    files: list[tuple[str, int, int]] = []
    try:
        with os.scandir(_to_scan_path(path)) as entries:
            for entry in entries:
                try:
                    is_link, st = _is_reparse_link(entry)
                    if is_link or entry.is_dir(follow_symlinks=False):
                        continue
                    if st is None:
                        st = entry.stat(follow_symlinks=False)
                    disk_bytes, cloud_bytes = _get_file_disk_size(
                        _strip_scan_prefix(entry.path), st
                    )
                    files.append((entry.name, disk_bytes, cloud_bytes))
                except OSError:
                    continue
    except OSError:
        return []
    files.sort(key=lambda item: (item[1], item[2]), reverse=True)
    return files


def _is_under_path(candidate_path: str, parent_path: str) -> bool:
    """Return True if candidate_path is strictly inside parent_path."""
    parent_norm = os.path.normcase(parent_path.rstrip("\\/"))
    cand_norm = os.path.normcase(candidate_path.rstrip("\\/"))
    if cand_norm == parent_norm:
        return False
    prefix = parent_norm + os.sep
    return cand_norm.startswith(prefix)


def get_cleanup_suggestions(
    current_path: str,
    cleanup_index: dict[str, CleanupSuggestion],
) -> tuple[list[CleanupSuggestion], int, int]:
    """Return (deduplicated_suggestions, safe_total_bytes, review_total_bytes) inside current_path."""
    scoped = [
        item
        for item in cleanup_index.values()
        if item.size > 0 and _is_under_path(item.path, current_path)
    ]
    # Process shallower paths first so ancestor directories deduplicate nested children.
    scoped.sort(key=lambda item: (item.path.count(os.sep), -item.size))

    accepted: list[CleanupSuggestion] = []
    covered_dir_prefixes: list[str] = []

    for item in scoped:
        item_norm = os.path.normcase(item.path.rstrip("\\/"))
        if any(item_norm.startswith(prefix) for prefix in covered_dir_prefixes):
            continue
        accepted.append(item)
        if item.is_dir:
            covered_dir_prefixes.append(item_norm + os.sep)

    accepted.sort(key=lambda item: item.size, reverse=True)
    safe_total = sum(item.size for item in accepted if item.category == "Safe")
    review_total = sum(item.size for item in accepted if item.category == "Review")
    return accepted, safe_total, review_total


def _invalidate_and_rescan(
    current_path: str,
    drive_root: str,
    cache: dict[str, DirInfo],
    cleanup_index: dict[str, CleanupSuggestion],
) -> DirInfo | None:
    """Re-scan current_path and propagate any size/count delta to cached ancestors."""
    old_info = cache.get(current_path)
    prefix = current_path.rstrip("\\/") + os.sep

    for target_map in (cache, cleanup_index):
        stale_keys = [
            key
            for key in target_map
            if key == current_path or key.startswith(prefix)
        ]
        for key in stale_keys:
            del target_map[key]

    if not os.path.exists(_to_scan_path(current_path)):
        print(f"Folder no longer exists: {current_path}")
        return None

    new_info = scan_directory_tree(current_path, cache, cleanup_index)
    if new_info is None:
        return None

    if old_info is not None:
        d_size = new_info.total_size - old_info.total_size
        d_cloud = new_info.cloud_size - old_info.cloud_size
        d_files = new_info.total_files - old_info.total_files
        d_folders = new_info.total_folders - old_info.total_folders
        cursor = _normalize_win_root(os.path.dirname(current_path.rstrip("\\/")))
        while cursor and cursor != current_path:
            parent_info = cache.get(cursor)
            if parent_info is not None:
                parent_info.total_size = max(0, parent_info.total_size + d_size)
                parent_info.cloud_size = max(0, parent_info.cloud_size + d_cloud)
                parent_info.total_files = max(0, parent_info.total_files + d_files)
                parent_info.total_folders = max(0, parent_info.total_folders + d_folders)
            if _same_path(cursor, drive_root):
                break
            next_cursor = _normalize_win_root(os.path.dirname(cursor.rstrip("\\/")))
            if next_cursor == cursor:
                break
            cursor = next_cursor

    return new_info


def print_drives(drives: list[DriveInfo]) -> None:
    """Print occupied and free space summary for all detected drives."""
    print()
    print("=" * 78)
    print("                           DISK STORAGE ANALYZER")
    print("=" * 78)
    if not drives:
        print("No accessible drives found.")
        print("=" * 78)
        return

    for idx, drv in enumerate(drives, start=1):
        name = f"{drv.letter}:" if os.name == "nt" else drv.root
        label_part = f" ({drv.label})" if drv.label else ""
        occupied = format_bytes(drv.used)
        left = format_bytes(drv.free)
        total = format_bytes(drv.total)
        print(
            f"  [{idx}] {name:<3}{label_part:<16} "
            f"Occupied: {occupied:>10} / Left: {left:>10}  "
            f"(Total: {total}, {drv.used_percent:.1f}% used)"
        )
    print("=" * 78)


def _resolve_drive_choice(choice: str, drives: list[DriveInfo]) -> DriveInfo | None:
    """Match a user choice by 1-based number or drive letter (e.g. 'C', 'C:')."""
    cleaned = choice.strip().rstrip("\\/").rstrip(":")
    if cleaned.isdigit():
        idx = int(cleaned)
        if 1 <= idx <= len(drives):
            return drives[idx - 1]
    for drv in drives:
        if (
            cleaned.lower() == drv.letter.lower()
            or cleaned.lower() == drv.root.rstrip("\\/").lower()
        ):
            return drv
    return None


def _prompt_drive_selection(drives: list[DriveInfo]) -> DriveInfo | None:
    """Ask the user whether they want to inspect storage inside a drive."""
    if not drives:
        return None

    while True:
        try:
            answer = input("\nDo you want to know the storage inside a drive? (y/n): ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return None

        lower = answer.lower()
        if lower in ("n", "no", "q", "quit", "exit"):
            return None

        direct_match = _resolve_drive_choice(answer, drives)
        if direct_match is not None:
            return direct_match

        if lower in ("y", "yes"):
            if len(drives) == 1:
                return drives[0]
            while True:
                letters = ", ".join(drv.letter for drv in drives)
                try:
                    pick = input(
                        f"Select a drive by number (1-{len(drives)}) or letter ({letters}) [or 'q' to quit]: "
                    ).strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return None
                if pick.lower() in ("q", "quit", "exit", "n", "no"):
                    return None
                selected = _resolve_drive_choice(pick, drives)
                if selected is not None:
                    return selected
                print(f"Invalid drive selection '{pick}'. Please try again.")
        else:
            print("Please enter 'y' or 'n' (or type a drive letter like C).")


def _print_direct_files_view(current_path: str) -> None:
    """Display files directly inside current_path sorted by on-disk size."""
    files = list_direct_files(current_path)
    print()
    print("-" * 78)
    print(f"Files directly inside: {current_path}")
    print("-" * 78)
    if not files:
        print("  (No files directly in this folder.)")
    else:
        limit = 30
        for idx, (name, disk_sz, cloud_sz) in enumerate(files[:limit], start=1):
            display_name = name if len(name) <= 48 else name[:45] + "..."
            cloud_note = f"  [cloud: {format_bytes(cloud_sz)}]" if cloud_sz > 0 and disk_sz == 0 else ""
            print(f"  {idx:>3}  {display_name:<48}  {format_bytes(disk_sz):>11}{cloud_note}")
        if len(files) > limit:
            print(f"  ... and {len(files) - limit:,} more smaller files.")
    print("-" * 78)
    try:
        input("Press Enter to return to folder view...")
    except (EOFError, KeyboardInterrupt):
        print()


def _format_relative_path(full_path: str, base_path: str) -> str:
    """Return a clean relative path from base_path."""
    try:
        rel = os.path.relpath(full_path, base_path)
        return rel
    except ValueError:
        return full_path


def _print_cleanup_summary(
    current_path: str,
    suggestions: list[CleanupSuggestion],
    safe_total: int,
    review_total: int,
    term_width: int,
    show_all: bool = False,
) -> None:
    """Print read-only cleanup recommendations at the end of a folder view."""
    eq_sep = "=" * term_width
    dash_sep = "-" * term_width
    total_reclaimable = safe_total + review_total

    print()
    print(eq_sep)
    print("  CLEANUP SUGGESTIONS (Read-Only — Nothing Deleted)")
    print(eq_sep)

    if not suggestions:
        print("  No obvious cache, temp, or unused installer files detected here.")
        print(eq_sep)
        return

    print(
        f"  Estimated space you could free: ~{format_bytes(total_reclaimable)}  "
        f"(Safe Junk: ~{format_bytes(safe_total)} | Review First: ~{format_bytes(review_total)})"
    )
    print(dash_sep)

    limit = len(suggestions) if show_all else DEFAULT_SUGGESTION_LIMIT
    visible = suggestions[:limit]

    for idx, item in enumerate(visible, start=1):
        rel = _format_relative_path(item.path, current_path)
        tag = f"[{item.category}]"
        kind = "Folder" if item.is_dir else "File"
        print(f"  {idx:>2}  {tag:<8} {format_bytes(item.size):>10}  {rel}")
        print(f"      {kind}: {item.reason}")

    if not show_all and suggestions:
        if len(suggestions) > limit:
            print(
                f"\n  ... and {len(suggestions) - limit:,} more suggestion(s) "
                f"(type 'c' to view all {len(suggestions):,} & save .txt to Downloads)."
            )
        else:
            print("\n  Tip: type 'c' to export these cleanup suggestions to Downloads (.txt).")

    print("  Note: Read-only suggestions only. Nothing is deleted automatically.")
    print(eq_sep)


def _get_downloads_dir() -> Path:
    """Return the user's Windows Downloads folder path, falling back to ~/Downloads."""
    if os.name == "nt":
        try:
            class _GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", ctypes.c_uint32),
                    ("Data2", ctypes.c_uint16),
                    ("Data3", ctypes.c_uint16),
                    ("Data4", ctypes.c_ubyte * 8),
                ]

            folder_id = _GUID(
                0x374DE290,
                0x123F,
                0x4565,
                (ctypes.c_ubyte * 8)(0x91, 0x64, 0x39, 0xC4, 0x92, 0x5E, 0x46, 0x7B),
            )
            path_ptr = ctypes.c_void_p()
            shell32 = ctypes.windll.shell32
            ole32 = ctypes.windll.ole32
            shell32.SHGetKnownFolderPath.argtypes = [
                ctypes.POINTER(_GUID),
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.POINTER(ctypes.c_void_p),
            ]
            shell32.SHGetKnownFolderPath.restype = ctypes.c_long
            ole32.CoTaskMemFree.argtypes = [ctypes.c_void_p]
            ole32.CoTaskMemFree.restype = None

            hr = shell32.SHGetKnownFolderPath(
                ctypes.byref(folder_id), 0, None, ctypes.byref(path_ptr)
            )
            if path_ptr.value:
                resolved = Path(ctypes.wstring_at(path_ptr.value))
                ole32.CoTaskMemFree(path_ptr)
                if hr == 0 and resolved.exists():
                    return resolved
        except OSError:
            pass

    fallback = Path.home() / "Downloads"
    fallback.mkdir(parents=True, exist_ok=True)
    return fallback


def _export_cleanup_report(
    current_path: str,
    suggestions: list[CleanupSuggestion],
    safe_total: int,
    review_total: int,
) -> Path:
    """Write a read-only cleanup suggestions text report to the user's Downloads folder."""
    downloads_dir = _get_downloads_dir()
    now = datetime.now()
    base_name = f"cleanup_suggestions_{now.strftime('%Y-%m-%d_%H-%M-%S')}"
    report_path = downloads_dir / f"{base_name}.txt"
    suffix = 1
    while report_path.exists():
        report_path = downloads_dir / f"{base_name}_{suffix}.txt"
        suffix += 1

    total_reclaimable = safe_total + review_total
    eq_sep = "=" * 80
    dash_sep = "-" * 80
    lines: list[str] = [
        eq_sep,
        "  DISK STORAGE ANALYZER - CLEANUP SUGGESTIONS (Read-Only)",
        eq_sep,
        f"  Generated            : {now.strftime('%Y-%m-%d %H:%M:%S')}",
        f"  Location             : {current_path}",
        f"  Total Suggestions    : {len(suggestions):,}",
        f"  Estimated Freeable   : ~{format_bytes(total_reclaimable)} "
        f"(Safe Junk: ~{format_bytes(safe_total)} | Review First: ~{format_bytes(review_total)})",
        "  Note                 : Read-only suggestions only. Nothing was deleted automatically.",
        eq_sep,
        "",
    ]

    if not suggestions:
        lines.append("  No obvious cache, temp, or unused installer files detected here.")
    else:
        for idx, item in enumerate(suggestions, start=1):
            kind = "Folder" if item.is_dir else "File"
            tag = f"[{item.category}]"
            lines.append(f"  {idx:>4}. {tag:<8} {format_bytes(item.size):>10}  ({kind})")
            lines.append(f"         Path   : {item.path}")
            lines.append(f"         Reason : {item.reason}")
            lines.append(dash_sep)

    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def _print_all_cleanup_view(
    current_path: str,
    suggestions: list[CleanupSuggestion],
    safe_total: int,
    review_total: int,
) -> None:
    """Display all cleanup suggestions for current_path and export them to Downloads."""
    term_width = max(78, min(100, shutil.get_terminal_size((80, 24)).columns))
    _print_cleanup_summary(
        current_path,
        suggestions,
        safe_total,
        review_total,
        term_width,
        show_all=True,
    )
    try:
        saved_path = _export_cleanup_report(
            current_path, suggestions, safe_total, review_total
        )
        print(f"  Saved cleanup report to: {saved_path}")
    except OSError as exc:
        print(f"  Warning: Could not save cleanup report to Downloads ({exc}).")
    try:
        input("Press Enter to return to folder view...")
    except (EOFError, KeyboardInterrupt):
        print()


def _render_folder_view(
    drive: DriveInfo,
    info: DirInfo,
    sorted_children: list[DirInfo],
    suggestions: list[CleanupSuggestion],
    safe_total: int,
    review_total: int,
    show_all: bool,
) -> None:
    """Display folder space breakdown, navigation commands, and cleanup suggestions."""
    term_width = max(78, min(100, shutil.get_terminal_size((80, 24)).columns))
    sep = "-" * term_width

    print()
    print(sep)
    print(f"Location: {info.path}")
    print(
        f"On-disk size: {format_bytes(info.total_size)}  |  "
        f"Subfolders: {len(sorted_children):,}  |  "
        f"Direct files: {info.direct_file_count:,} ({format_bytes(info.direct_file_size)})"
    )
    if info.cloud_size > 0:
        print(
            f"Cloud/virtual files (0 B on SSD): {format_bytes(info.cloud_size)}"
        )
    print(
        f"Drive {drive.letter}:  "
        f"Occupied: {format_bytes(drive.used)}  /  Left: {format_bytes(drive.free)}  "
        f"(Total: {format_bytes(drive.total)})"
    )
    if _same_path(info.path, drive.root) and drive.used > info.total_size:
        unscanned_diff = drive.used - info.total_size
        if unscanned_diff >= 64 * 1024 * 1024:
            print(
                f"System overhead / protected folders (not readable without Admin): "
                f"~{format_bytes(unscanned_diff)}"
            )
    print(sep)

    if not sorted_children:
        print("  (No subfolders inside this folder.)")
        if info.direct_file_count > 0 or info.direct_cloud_size > 0:
            files = list_direct_files(info.path)
            file_limit = len(files) if show_all else DEFAULT_PAGE_SIZE
            name_col_width = max(24, term_width - 32)
            print()
            print(f" {'#':>3}  {'File Name':<{name_col_width}}  {'On-Disk':>11}  {'%':>6}")
            print(sep)
            for idx, (fname, disk_sz, cloud_sz) in enumerate(files[:file_limit], start=1):
                display_name = (
                    fname
                    if len(fname) <= name_col_width
                    else fname[: name_col_width - 3] + "..."
                )
                pct = (disk_sz / info.total_size * 100.0) if info.total_size > 0 else 0.0
                cloud_tag = f" [cloud: {format_bytes(cloud_sz)}]" if cloud_sz > 0 and disk_sz == 0 else ""
                print(
                    f" {idx:>3}  {display_name:<{name_col_width}}  "
                    f"{format_bytes(disk_sz):>11}  {pct:>5.1f}%{cloud_tag}"
                )
            if len(files) > file_limit:
                print(
                    f"\n  ... {len(files) - file_limit:,} more smaller files hidden "
                    f"(type 'a' to show all)."
                )
    else:
        limit = len(sorted_children) if show_all else DEFAULT_PAGE_SIZE
        visible = sorted_children[:limit]
        name_col_width = max(24, term_width - 42)
        print(
            f" {'#':>3}  {'Folder Name':<{name_col_width}}  "
            f"{'On-Disk':>11}  {'%':>6}  {'Subfolders'}"
        )
        print(sep)

        for idx, child in enumerate(visible, start=1):
            folder_name = os.path.basename(child.path) or child.path
            if len(folder_name) > name_col_width:
                folder_name = folder_name[: name_col_width - 3] + "..."
            pct = (child.total_size / info.total_size * 100.0) if info.total_size > 0 else 0.0
            sub_label = f"Yes ({len(child.subdirs)})" if child.subdirs else "No"
            if child.cloud_size > 0 and child.total_size == 0:
                sub_label += f" [{format_bytes(child.cloud_size)} cloud]"
            print(
                f" {idx:>3}  {folder_name:<{name_col_width}}  "
                f"{format_bytes(child.total_size):>11}  {pct:>5.1f}%  {sub_label}"
            )

        if len(sorted_children) > len(visible):
            hidden = len(sorted_children) - len(visible)
            print(f"\n  ... {hidden:,} more smaller folders hidden (type 'a' to show all).")

    if info.direct_file_count > 0:
        file_pct = (
            info.direct_file_size / info.total_size * 100.0 if info.total_size > 0 else 0.0
        )
        print(
            f"\n  [Files directly in this folder]  "
            f"{format_bytes(info.direct_file_size)} ({file_pct:.1f}% across {info.direct_file_count:,} files)"
        )

    if info.error_count > 0:
        print(
            f"  Note: {info.error_count:,} protected system item(s) could not be accessed."
        )

    _print_cleanup_summary(
        info.path,
        suggestions,
        safe_total,
        review_total,
        term_width,
        show_all=False,
    )

    print("Commands:")
    if sorted_children:
        print("  <number> or <name>  Open a folder to see storage inside it")
        if len(sorted_children) > DEFAULT_PAGE_SIZE:
            toggle_hint = (
                f"Show top {DEFAULT_PAGE_SIZE} folders"
                if show_all
                else f"Show all {len(sorted_children):,} folders"
            )
            print(f"  a                   {toggle_hint}")
        print("  f                   Show largest files directly in this folder")
    elif info.direct_file_count > DEFAULT_PAGE_SIZE:
        toggle_hint = (
            f"Show top {DEFAULT_PAGE_SIZE} files"
            if show_all
            else f"Show all {info.direct_file_count:,} files"
        )
        print(f"  a                   {toggle_hint}")
    if suggestions:
        print(
            f"  c                   View all {len(suggestions):,} cleanup suggestions "
            f"& save .txt to Downloads"
        )
    if _same_path(info.path, drive.root):
        print("  b / .. / d          Back to drive list")
    else:
        print("  b / ..              Go back to parent folder")
        print("  d                   Switch drive / view all drives")
    print("  r                   Re-scan current folder")
    print("  q                   Quit")


def _resolve_folder_choice(choice: str, sorted_children: list[DirInfo]) -> DirInfo | None:
    """Match user input to a child directory by 1-based index or folder name."""
    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(sorted_children):
            return sorted_children[idx - 1]

    for child in sorted_children:
        if os.path.basename(child.path) == choice:
            return child
    lower = choice.lower()
    for child in sorted_children:
        if os.path.basename(child.path).lower() == lower:
            return child
    return None


def browse_drive(
    drive: DriveInfo,
    cache: dict[str, DirInfo],
    cleanup_index: dict[str, CleanupSuggestion],
) -> str:
    """Interactive folder drill-down loop inside a selected drive."""
    current_path = drive.root
    show_all = False

    while True:
        info = cache.get(current_path)
        if info is None:
            info = scan_directory_tree(current_path, cache, cleanup_index)
            if info is None:
                return "drives"

        sorted_children = sorted(
            (cache[sub] for sub in info.subdirs if sub in cache),
            key=lambda item: (item.total_size, item.cloud_size),
            reverse=True,
        )
        suggestions, safe_total, review_total = get_cleanup_suggestions(
            current_path, cleanup_index
        )
        _render_folder_view(
            drive,
            info,
            sorted_children,
            suggestions,
            safe_total,
            review_total,
            show_all,
        )

        try:
            raw = input("\nEnter choice: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return "quit"

        if not raw:
            continue

        lower = raw.lower()
        if lower in ("q", "quit", "exit"):
            return "quit"
        if lower in ("d", "drives"):
            return "drives"
        if lower in ("b", "back", ".."):
            if _same_path(current_path, drive.root):
                return "drives"
            current_path = _normalize_win_root(
                os.path.dirname(current_path.rstrip("\\/"))
            )
            show_all = False
            continue
        if lower in ("a", "all"):
            show_all = not show_all
            continue
        if lower in ("f", "files"):
            _print_direct_files_view(current_path)
            continue
        if lower in ("c", "cleanup"):
            _print_all_cleanup_view(current_path, suggestions, safe_total, review_total)
            continue
        if lower in ("r", "refresh"):
            updated = _invalidate_and_rescan(
                current_path, drive.root, cache, cleanup_index
            )
            if updated is None and not os.path.exists(_to_scan_path(current_path)):
                if _same_path(current_path, drive.root):
                    return "drives"
                current_path = _normalize_win_root(
                    os.path.dirname(current_path.rstrip("\\/"))
                )
            continue

        selected = _resolve_folder_choice(raw, sorted_children)
        if selected is not None:
            current_path = selected.path
            show_all = False
        else:
            print(
                f"Folder not found: '{raw}'. Enter a folder number, folder name, or command."
            )


def main() -> None:
    """Entry point for the interactive storage analyzer."""
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    cache: dict[str, DirInfo] = {}
    cleanup_index: dict[str, CleanupSuggestion] = {}

    while True:
        drives = get_available_drives()
        print_drives(drives)

        selected_drive = _prompt_drive_selection(drives)
        if selected_drive is None:
            print("Goodbye!")
            break

        action = browse_drive(selected_drive, cache, cleanup_index)
        if action == "quit":
            print("Goodbye!")
            break


if __name__ == "__main__":
    main()
