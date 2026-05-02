import pytest
import os
from pathlib import Path
from soc_analyzer_pro.src.utils import validate_path

def test_path_traversal_shield(tmp_path):
    """Ensure PermissionError is raised on traversal attempts."""
    base_dir = tmp_path / "authorized"
    base_dir.mkdir()
    malicious_input = "../../../etc/passwd"
    
    with pytest.raises(PermissionError, match="Security Violation"):
        validate_path(malicious_input, base_dir=str(base_dir))

def test_empty_file_guard(tmp_path):
    """Ensure ValueError is raised on empty files (pre-flight check)."""
    base_dir = tmp_path / "logs"
    base_dir.mkdir()
    empty_log = base_dir / "empty.log"
    empty_log.write_text("")
    
    with pytest.raises(ValueError, match="is empty"):
        validate_path(str(empty_log), base_dir=str(base_dir))

def test_valid_path_resolution(tmp_path):
    """Ensure legitimate paths are resolved correctly."""
    base_dir = tmp_path / "logs"
    base_dir.mkdir()
    valid_log = base_dir / "access.log"
    valid_log.write_text("127.0.0.1 - test log")
    
    resolved = validate_path(str(valid_log), base_dir=str(base_dir))
    assert resolved.name == "access.log"
    assert resolved.exists()