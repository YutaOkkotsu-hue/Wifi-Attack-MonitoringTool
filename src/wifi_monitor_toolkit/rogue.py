from __future__ import annotations

import json
from pathlib import Path

from .models import AccessPoint, RogueFinding, normalize_mac
from .scanner import collect_access_points


def load_trusted(path: str | Path) -> dict[str, AccessPoint]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    trusted: dict[str, AccessPoint] = {}
    for item in raw:
        bssid = normalize_mac(item.get("bssid"))
        trusted[bssid] = AccessPoint(
            ssid=str(item.get("ssid", "")),
            bssid=bssid,
            channel=item.get("channel"),
            crypto=set(item.get("crypto", [])),
        )
    return trusted


def find_rogues(observed: dict[str, AccessPoint], trusted: dict[str, AccessPoint]) -> list[RogueFinding]:
    findings: list[RogueFinding] = []
    trusted_by_ssid: dict[str, set[str]] = {}
    for ap in trusted.values():
        trusted_by_ssid.setdefault(ap.ssid, set()).add(ap.bssid)

    for bssid, ap in observed.items():
        expected = trusted.get(bssid)
        if expected is None:
            if ap.ssid in trusted_by_ssid:
                findings.append(
                    RogueFinding(
                        severity="high",
                        bssid=bssid,
                        ssid=ap.ssid,
                        reason="Unknown BSSID is broadcasting a trusted SSID",
                    )
                )
            continue

        if ap.ssid != expected.ssid:
            findings.append(
                RogueFinding(
                    severity="medium",
                    bssid=bssid,
                    ssid=ap.ssid,
                    reason=f"Known BSSID changed SSID from {expected.ssid!r}",
                )
            )

        if expected.channel is not None and ap.channel is not None and ap.channel != expected.channel:
            findings.append(
                RogueFinding(
                    severity="low",
                    bssid=bssid,
                    ssid=ap.ssid,
                    reason=f"Known BSSID changed channel from {expected.channel} to {ap.channel}",
                )
            )

        if expected.crypto and ap.crypto and "UNKNOWN" not in ap.crypto and ap.crypto != expected.crypto:
            findings.append(
                RogueFinding(
                    severity="medium",
                    bssid=bssid,
                    ssid=ap.ssid,
                    reason=f"Known BSSID changed crypto from {sorted(expected.crypto)} to {sorted(ap.crypto)}",
                )
            )

    return findings


def scan_for_rogues(iface: str, trusted_path: str | Path, seconds: int) -> list[RogueFinding]:
    return find_rogues(collect_access_points(iface, seconds), load_trusted(trusted_path))
