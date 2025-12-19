"""
hashing.py
-----------
Utility functions for hashing files.

This module provides a function to compute the SHA-256 hash of a file.
Used by the File Integrity Monitor to detect file changes.
"""

import hashlib
from pathlib import Path

# Read files in chunks to support large files efficiently
CHUNK_SIZE = 1024 * 1024  # 1 MB


def sha256_file(path: Path) -> str:
    """
    Compute the SHA-256 hash of a file.

    Args:
        path (Path): Path to the file.

    Returns:
        str: Hexadecimal SHA-256 digest of the file.
    """
    h = hashlib.sha256()

    # Open file in binary mode
    with path.open("rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)

    return h.hexdigest()
