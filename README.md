# Disk Storage Analyzer (`analyze.py`)

An interactive Python CLI tool that displays occupied and free space across every drive, lets you drill down recursively into folders to inspect what is taking up storage, provides **read-only cleanup suggestions** at the end of every view, and exports full cleanup reports to your `Downloads` folder.

> **Read-Only Safety Guarantee:** This tool never deletes, moves, or modifies any user files or folders. Cleanup suggestions only advise what you can safely inspect or remove manually.

---

## Requirements

- **Python 3.10+** (tested with Python 3.14)
- **Zero third-party dependencies** — uses only Python's standard library (`ctypes`, `os`, `queue`, `shutil`, `stat`, `sys`, `threading`, `time`, `dataclasses`, `datetime`, `pathlib`)
- Primarily built for **Windows** (with POSIX `/` fallback)

---

## Quick Start

```powershell
python analyze.py
```

*(Tip: Run an elevated Administrator terminal only if you also want protected system folders such as `System Volume Information` or restricted Windows directories included in subfolder breakdowns.)*

---

## Key Features

### 1. Drive Overview
When launched, the analyzer detects all accessible drives and displays space in **base-1024 units** (`B`, `KB`, `MB`, `GB`, `TB`, `PB`) matching Windows Explorer:

```text
==============================================================================
                           DISK STORAGE ANALYZER
==============================================================================
  [1] C:                  Occupied:  281.57 GB / Left:   23.89 GB  (Total: 305.46 GB, 92.2% used)
  [2] D:                  Occupied:  113.43 GB / Left:   56.57 GB  (Total: 170.00 GB, 66.7% used)
==============================================================================
```

### 2. Accurate Windows On-Disk Accounting
- **Cloud / Virtual Placeholders:** Files marked `OFFLINE`, `RECALL_ON_OPEN`, or `RECALL_ON_DATA_ACCESS` (such as CrossDevice or online-only OneDrive files) consume `0 B` locally and are excluded from on-disk totals, then summarized separately (`Cloud/virtual files (0 B on SSD)`).
- **NTFS Compressed & Sparse Files:** Uses Windows `GetCompressedFileSizeW` to read actual allocated bytes on disk.
- **No Double Counting:** Skips symlinks and Windows directory junctions (`IO_REPARSE_TAG_MOUNT_POINT`, `IO_REPARSE_TAG_SYMLINK`).
- **Long Paths & Protected Items:** Automatically applies Windows `\\?\` extended path prefixes for paths `>= 240` characters and transparently reports protected system overhead (`System overhead / protected folders (not readable without Admin)`).

### 3. Fast Parallel Scanning & Cached Navigation
- Uses a multi-threaded work-stealing scanner (`8`–`16` workers) with bottom-up tree aggregation.
- Navigating deeper into subfolders reuses the scanned in-memory cache instantly; press `r` whenever you want to re-scan a folder after making changes on disk.

### 4. Read-Only Cleanup Suggestions (`[Safe]` vs `[Review]`)
Every folder view ends with a deduplicated summary of reclaimable items inside the current folder:

- **`[Safe]`** — Caches, temporary files, crash dumps, and logs that are safe to clear and automatically recreated as needed:
  - System/user temp & dump locations (`Windows\Temp`, `Windows\SoftwareDistribution\Download`, `Windows\Minidump`, `Windows\LiveKernelReports`, `AppData\Local\Temp`, `AppData\Local\CrashDumps`, `$Recycle.Bin`, `OneDriveTemp`)
  - Developer & browser caches (`pip\cache`, `npm-cache`, `_cacache`, `NuGet\v3-cache`, `.gradle\caches`, `.next\cache`, `node_modules\.cache`, `go-build`, `go\pkg\mod\cache\download`, `.wdm`, `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache`, `.cache`, and AppData browser `Cache` / `Code Cache` / `GPUCache` / `ShaderCache`)
  - Temp/log/dump files (`>= 100 KB`): `.tmp`, `.temp`, `.dmp`, `.hdmp`, `.mdmp`, `.etl`, `.bak`, `.old`, `.log`
  - Metadata caches (`>= 1 KB`): `Thumbs.db`, `.DS_Store`
- **`[Review]`** — Large items that can reclaim substantial space but should be reviewed before deleting manually:
  - Project/environment directories (`node_modules`, `.next`, `.nuxt`, `.venv`, `venv`, `temp`, `tmp`)
  - Large tool data (`.ollama` AI models, `.android\avd` emulator images)
  - Large archives/disk images/installers (`>= 10 MB` normally, or `>= 1 MB` inside `Downloads`): `.zip`, `.rar`, `.7z`, `.tar`, `.gz`, `.iso`, `.img`, `.msi`, `.msix`, `.cab`, and installer `.exe` files in `Downloads` / `Desktop` / drive root or named with `setup` / `install` / `installer` (installed apps, Windows, Program Files, and SDK directories are excluded)

### 5. Export Cleanup Report to `Downloads`
Choosing `c` (or `cleanup`) inside any folder displays **all** cleanup suggestions for that path and automatically writes a timestamped report to your Windows `Downloads` folder:

```text
cleanup_suggestions_YYYY-MM-DD_HH-MM-SS.txt
```

- Resolves your Windows `Downloads` path automatically (`FOLDERID_Downloads`, falling back to `~/Downloads`).
- If multiple reports are generated within the same second, `_1`, `_2`, etc. are appended so existing reports are never overwritten.
- Lists every suggestion with its category (`[Safe]` / `[Review]`), size, type (`Folder` / `File`), full disk path, and cleanup reason.

---

## Interactive Commands

### At the Drive Prompt
| Input | Action |
| :--- | :--- |
| `y` / `yes` | Prompt to pick a drive to inspect |
| `<number>` or `<letter>` (e.g. `1`, `C`, `D`) | Jump directly into inspecting that drive |
| `n` / `q` / `quit` / `exit` | Exit the program |

### Inside a Drive / Folder
| Command | Action |
| :--- | :--- |
| `<number>` or `<folder name>` | Open a subfolder and inspect its contents |
| `a` / `all` | Toggle between top `25` items and all folders/files |
| `f` / `files` | List up to top `30` largest files directly inside the current folder |
| `c` / `cleanup` | Show all cleanup suggestions and export `cleanup_suggestions_{date+time}.txt` to `Downloads` |
| `b` / `back` / `..` | Go back to the parent folder (or drive list if at drive root) |
| `d` / `drives` | Switch drives / return to drive overview |
| `r` / `refresh` | Re-scan the current folder from disk |
| `q` / `quit` / `exit` | Exit the program |
