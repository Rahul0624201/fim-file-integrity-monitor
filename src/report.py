"""
report.py
----------
Handles writing scan results to JSON and CSV files.
"""

import csv
import json
from pathlib import Path
from typing import Dict, Any, List


def write_json(data: Dict[str, Any], out_path: Path) -> None:
    """
    Write a dictionary to a JSON file.

    Args:
        data (dict): Data to write.
        out_path (Path): Output JSON file path.
    """
    # Ensure output directory exists
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # Write pretty-formatted JSON
    out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def write_csv(rows: List[dict], out_path: Path, fieldnames: List[str]) -> None:
    """
    Write rows of data to a CSV file.

    Args:
        rows (list[dict]): List of rows to write.
        out_path (Path): Output CSV file path.
        fieldnames (list[str]): CSV column headers.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
