from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class AircrackCheck:
    available: bool
    handshake_seen: bool
    summary: str


def check_capture(path: str, timeout: int = 30) -> AircrackCheck:
    binary = shutil.which("aircrack-ng")
    if binary is None:
        return AircrackCheck(False, False, "aircrack-ng was not found in PATH")

    completed = subprocess.run(
        [binary, path],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    output = f"{completed.stdout}\n{completed.stderr}"
    handshake_seen = bool(re.search(r"\bhandshake\b", output, re.IGNORECASE))
    summary = _compact_output(output)
    return AircrackCheck(True, handshake_seen, summary)


def _compact_output(output: str) -> str:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    interesting = [
        line
        for line in lines
        if "handshake" in line.lower() or "bssid" in line.lower() or "essid" in line.lower()
    ]
    return "\n".join(interesting[:12]) or "\n".join(lines[-12:])
