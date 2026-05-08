from __future__ import annotations

from .models import AccessPoint, DeauthEvent, HandshakeEvent, normalize_mac
from .scapy_compat import load_scapy


_SCAPY: dict | None = None


def _layers() -> dict:
    global _SCAPY
    if _SCAPY is None:
        _SCAPY = load_scapy()
    return _SCAPY


def parse_ap(packet) -> AccessPoint | None:
    layers = _layers()
    Dot11 = layers["Dot11"]
    Dot11Beacon = layers["Dot11Beacon"]
    Dot11ProbeResp = layers["Dot11ProbeResp"]
    if not packet.haslayer(Dot11) or not (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp)):
        return None

    dot11 = packet.getlayer(Dot11)
    bssid = normalize_mac(dot11.addr3)
    if not bssid:
        return None

    ssid = _ssid(packet)
    channel = _channel(packet)
    signal = _signal(packet)
    crypto = _crypto(packet)
    return AccessPoint(ssid=ssid, bssid=bssid, channel=channel, signal_dbm=signal, crypto=crypto, frames=1)


def parse_deauth(packet) -> DeauthEvent | None:
    layers = _layers()
    Dot11 = layers["Dot11"]
    Dot11Deauth = layers["Dot11Deauth"]
    if not packet.haslayer(Dot11) or not packet.haslayer(Dot11Deauth):
        return None

    dot11 = packet.getlayer(Dot11)
    deauth = packet.getlayer(Dot11Deauth)
    return DeauthEvent(
        source=normalize_mac(dot11.addr2),
        destination=normalize_mac(dot11.addr1),
        bssid=normalize_mac(dot11.addr3),
        reason=getattr(deauth, "reason", None),
        timestamp=float(getattr(packet, "time", 0.0)),
    )


def parse_handshake(packet) -> HandshakeEvent | None:
    layers = _layers()
    Dot11 = layers["Dot11"]
    EAPOL = layers["EAPOL"]
    if not packet.haslayer(Dot11) or not packet.haslayer(EAPOL):
        return None

    dot11 = packet.getlayer(Dot11)
    src = normalize_mac(dot11.addr2)
    dst = normalize_mac(dot11.addr1)
    bssid = normalize_mac(dot11.addr3) or None
    hint = "EAPOL key frame"
    return HandshakeEvent(
        source=src,
        destination=dst,
        bssid=bssid,
        timestamp=float(getattr(packet, "time", 0.0)),
        message_hint=hint,
    )


def _ssid(packet) -> str:
    Dot11Elt = _layers()["Dot11Elt"]
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        if getattr(elt, "ID", None) == 0:
            raw = bytes(getattr(elt, "info", b""))
            return raw.decode(errors="replace") or "<hidden>"
        elt = getattr(elt, "payload", None)
        if not isinstance(elt, Dot11Elt):
            break
    return "<unknown>"


def _channel(packet) -> int | None:
    Dot11Elt = _layers()["Dot11Elt"]
    elt = packet.getlayer(Dot11Elt)
    while elt is not None:
        if getattr(elt, "ID", None) == 3:
            info = bytes(getattr(elt, "info", b""))
            if info:
                return info[0]
        elt = getattr(elt, "payload", None)
        if not isinstance(elt, Dot11Elt):
            break
    return None


def _signal(packet) -> int | None:
    RadioTap = _layers()["RadioTap"]
    if packet.haslayer(RadioTap):
        dbm = getattr(packet.getlayer(RadioTap), "dBm_AntSignal", None)
        if isinstance(dbm, int):
            return dbm
    return None


def _crypto(packet) -> set[str]:
    Dot11Beacon = _layers()["Dot11Beacon"]
    crypto: set[str] = set()
    beacon = packet.getlayer(Dot11Beacon)
    if beacon is None:
        beacon = packet
    network_stats = getattr(beacon, "network_stats", None)
    if callable(network_stats):
        try:
            parsed = network_stats()
            values = parsed.get("crypto", set())
            crypto.update(str(item) for item in values)
        except Exception:
            pass
    return crypto or {"UNKNOWN"}
