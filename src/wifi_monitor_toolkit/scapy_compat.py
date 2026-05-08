from __future__ import annotations

from typing import Any


class ScapyMissingError(RuntimeError):
    pass


def load_scapy() -> dict[str, Any]:
    try:
        from scapy.all import Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeResp, EAPOL, RadioTap, rdpcap, sniff
    except ImportError as exc:
        raise ScapyMissingError(
            "Scapy is required. Install dependencies with: pip install -r requirements.txt"
        ) from exc

    return {
        "Dot11": Dot11,
        "Dot11Beacon": Dot11Beacon,
        "Dot11Deauth": Dot11Deauth,
        "Dot11Elt": Dot11Elt,
        "Dot11ProbeResp": Dot11ProbeResp,
        "EAPOL": EAPOL,
        "RadioTap": RadioTap,
        "rdpcap": rdpcap,
        "sniff": sniff,
    }
