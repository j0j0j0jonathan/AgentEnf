"""Acceptance test with the separately installed EnfGuard monitor."""
import os
import subprocess
import sys
from pathlib import Path
import pytest

def test_live_monitor_allow_block_and_approval():
    binary = os.environ.get("ENFGUARD_BIN", "")
    if not binary or not Path(binary).is_file():
        pytest.skip("Set ENFGUARD_BIN for the live monitor acceptance test")
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run([sys.executable, str(root / "tests/monitor_smoke.py")],
                            cwd=root, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS: real monitor" in result.stdout
