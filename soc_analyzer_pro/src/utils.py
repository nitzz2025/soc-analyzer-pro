import os
import logging
from pathlib import Path

def validate_path(user_input: str, base_dir: str = "/content") -> Path:
    """
    Strict Path Validation using Zero-Trust principles.
    Includes Path Traversal Shield and Empty-File Guard.
    """
    base_path = Path(base_dir).resolve()
    safe_path = Path(user_input).resolve()

    # 1. Path Traversal Shield
    if not safe_path.is_relative_to(base_path):
        logging.critical(f"TRAVERSAL ATTEMPT: {user_input}")
        raise PermissionError(f"Security Violation: {user_input} is outside authorized scope.")

    # 2. Existence Check
    if not safe_path.exists():
        raise FileNotFoundError(f"Log source not found: {safe_path}")

    # 3. Empty File Guard (Zero-Error Pre-flight)
    if safe_path.is_file() and os.path.getsize(safe_path) == 0:
        logging.error(f"ZERO-BYTE FILE detected: {safe_path}")
        raise ValueError(f"Ingestion Failed: File {safe_path.name} is empty.")

    return safe_path