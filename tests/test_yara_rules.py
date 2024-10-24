from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
YARA_RULE = ROOT / "rules/yara/malware_families.yar"


def _write_loader_sample(path: Path) -> None:
    """MZ + strings satisfying Lab_C2_Loader_Dll for yara CLI validation."""
    content = bytearray()
    content.extend(b"MZ\x90\x00")
    content.extend(b"\x00" * 64)
    content.extend(b"ReflectiveLoader\x00")
    content.extend(b"VirtualAlloc\x00")
    content.extend(b"WriteProcessMemory\x00")
    path.write_bytes(content)


def _write_phishing_macro_sample(path: Path) -> None:
    path.write_text(
        "Auto_Open powershell.exe -enc abc",
        encoding="utf-8",
    )


@pytest.mark.skipif(not shutil.which("yara"), reason="yara not installed")
def test_yara_compiles_and_matches():
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        loader = tmp / "loader.bin"
        macro = tmp / "macro.txt"
        _write_loader_sample(loader)
        _write_phishing_macro_sample(macro)
        r = subprocess.run(
            ["yara", "-s", str(YARA_RULE), str(tmp)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert not r.stderr or "error" not in r.stderr.lower(), r.stderr
        out = r.stdout
        assert "Lab_C2_Loader_Dll" in out
        assert "Lab_Phishing_Doc_Macro" in out
