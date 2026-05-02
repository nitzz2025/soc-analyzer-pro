import os
from pathlib import Path

def validate_path(path_str: str, base_dir: str = "/content") -> Path:
    """Security-hardened path validation."""
    target = Path(path_str).resolve()
    base = Path(base_dir).resolve()
    if not str(target).startswith(str(base)):
        raise PermissionError(f"[SEC-ERR] Security Violation: Path {path_str} is outside authorized zone.")
    if target.exists() and target.stat().st_size == 0:
        raise ValueError(f"[SEC-ERR] Validation Failed: File {path_str} is empty.")
    return target