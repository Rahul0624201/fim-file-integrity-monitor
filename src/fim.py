"""
fim.py
------
File Integrity Monitor (FIM)

Creates a baseline of file hashes for a directory and later scans to
detect added, removed, or modified files.

Usage:
    python -m src.fim --dir <path> --init
    python -m src.fim --dir <path> --scan
"""

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple

from .hashing import sha256_file
from .report import write_json, write_csv


def utc_now() -> str:
    """
    Get the current UTC time in ISO format.

    Returns:
        str: UTC timestamp string.
    """
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def iter_files(root: Path, recursive: bool, exclude: list[str]) -> List[Path]:
    """
    Collect files from a directory.

    Args:
        root (Path): Directory to scan.
        recursive (bool): Whether to scan recursively.
        exclude (list[str]): Tokens to exclude from paths.

    Returns:
        list[Path]: Sorted list of file paths.
    """
    # Choose recursive or non-recursive scan
    if recursive:
        files = [p for p in root.rglob("*") if p.is_file()]
    else:
        files = [p for p in root.glob("*") if p.is_file()]

    # Filter out excluded paths
    def is_excluded(p: Path) -> bool:
        s = str(p).lower()
        return any(token.lower() in s for token in exclude)

    files = [p for p in files if not is_excluded(p)]
    return sorted(files, key=lambda p: str(p).lower())


def build_baseline(target_dir: Path, recursive: bool, exclude: list[str]) -> Dict[str, str]:
    """
    Build a baseline mapping of relative file paths to SHA-256 hashes.

    Args:
        target_dir (Path): Directory to monitor.
        recursive (bool): Whether to scan recursively.
        exclude (list[str]): Exclusion tokens.

    Returns:
        dict[str, str]: Baseline of file hashes.
    """
    baseline: Dict[str, str] = {}

    for p in iter_files(target_dir, recursive, exclude):
        rel_path = str(p.relative_to(target_dir))
        baseline[rel_path] = sha256_file(p)

    return baseline


def load_baseline(path: Path) -> Dict[str, str]:
    """
    Load baseline file from disk.

    Args:
        path (Path): Baseline JSON file.

    Returns:
        dict[str, str]: Loaded baseline mapping.
    """
    data = json.loads(path.read_text(encoding="utf-8"))

    # Accept {"files": {...}} or a flat dict
    if isinstance(data, dict) and "files" in data:
        return data["files"]

    if isinstance(data, dict):
        return {k: v for k, v in data.items() if isinstance(v, str)}

    raise ValueError("Baseline file format not recognized.")


def compare_baseline(
    target_dir: Path,
    baseline: Dict[str, str],
    recursive: bool,
    exclude: list[str]
) -> Tuple[list[str], list[str], list[str]]:
    """
    Compare current directory state to baseline.

    Returns:
        (added, removed, modified)
    """
    current = build_baseline(target_dir, recursive, exclude)

    baseline_paths = set(baseline.keys())
    current_paths = set(current.keys())

    # New files
    added = sorted(list(current_paths - baseline_paths))

    # Deleted files
    removed = sorted(list(baseline_paths - current_paths))

    # Changed files
    modified = []
    for path in sorted(list(current_paths & baseline_paths)):
        if current[path] != baseline[path]:
            modified.append(path)

    return added, removed, modified


def main() -> int:
    """
    Main CLI entry point.
    """
    parser = argparse.ArgumentParser(description="File Integrity Monitor (FIM)")
    parser.add_argument("--dir", required=True, help="Directory to monitor")
    parser.add_argument("--baseline", default="output/baseline.json", help="Baseline JSON file path")
    parser.add_argument("--recursive", action="store_true", help="Scan directories recursively")
    parser.add_argument("--exclude", default="", help="Comma-separated exclude tokens")
    parser.add_argument("--init", action="store_true", help="Create baseline")
    parser.add_argument("--scan", action="store_true", help="Scan and compare to baseline")

    args = parser.parse_args()

    target_dir = Path(args.dir).expanduser().resolve()
    baseline_path = Path(args.baseline).expanduser().resolve()
    exclude = [x.strip() for x in args.exclude.split(",") if x.strip()]

    # Validate directory
    if not target_dir.exists() or not target_dir.is_dir():
        print(f"[ERROR] Directory not found: {target_dir}")
        return 2

    if not args.init and not args.scan:
        print("[ERROR] Choose either --init or --scan")
        return 2

    # Initialize baseline
    if args.init:
        files = build_baseline(target_dir, args.recursive, exclude)

        payload: Dict[str, Any] = {
            "generated_at": utc_now(),
            "target_dir": str(target_dir),
            "recursive": bool(args.recursive),
            "exclude": exclude,
            "files": files,
        }

        write_json(payload, baseline_path)
        print(f"[OK] Baseline created: {baseline_path}")
        print(f"[OK] Tracked files: {len(files)}")
        return 0

    # Scan mode
    if not baseline_path.exists():
        print(f"[ERROR] Baseline not found: {baseline_path}")
        print("Run with --init first.")
        return 2

    baseline = load_baseline(baseline_path)
    added, removed, modified = compare_baseline(target_dir, baseline, args.recursive, exclude)

    result = {
        "scanned_at": utc_now(),
        "target_dir": str(target_dir),
        "baseline": str(baseline_path),
        "added": added,
        "removed": removed,
        "modified": modified,
        "counts": {
            "added": len(added),
            "removed": len(removed),
            "modified": len(modified),
        },
    }

    out_json = Path("output/scan_report.json")
    out_csv = Path("output/scan_report.csv")

    # Save reports
    write_json(result, out_json)

    rows = []
    for p in added:
        rows.append({"change_type": "ADDED", "path": p})
    for p in removed:
        rows.append({"change_type": "REMOVED", "path": p})
    for p in modified:
        rows.append({"change_type": "MODIFIED", "path": p})

    write_csv(rows, out_csv, fieldnames=["change_type", "path"])

    print("[OK] Scan complete")
    print(f"Added: {len(added)} | Removed: {len(removed)} | Modified: {len(modified)}")
    print(f"Saved: {out_json}")
    print(f"Saved: {out_csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
