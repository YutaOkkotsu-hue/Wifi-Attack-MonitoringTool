from __future__ import annotations

from collections.abc import Iterable

from .frame_parsing import parse_ap
from .models import AccessPoint
from .scapy_compat import load_scapy


def collect_access_points(iface: str, seconds: int) -> dict[str, AccessPoint]:
    scapy = load_scapy()
    aps: dict[str, AccessPoint] = {}

    def handle(packet) -> None:
        ap = parse_ap(packet)
        if ap is None:
            return
        if ap.bssid in aps:
            aps[ap.bssid].update(
                ssid=ap.ssid,
                channel=ap.channel,
                signal_dbm=ap.signal_dbm,
                crypto=ap.crypto,
            )
        else:
            aps[ap.bssid] = ap

    scapy["sniff"](iface=iface, prn=handle, timeout=seconds, store=False)
    return aps


def summarize_aps(aps: Iterable[AccessPoint]) -> list[dict[str, object]]:
    return sorted((ap.as_dict() for ap in aps), key=lambda item: (str(item["ssid"]), str(item["bssid"])))
