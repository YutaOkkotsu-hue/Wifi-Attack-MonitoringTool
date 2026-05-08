from __future__ import annotations

from collections import Counter, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from time import monotonic

from .frame_parsing import parse_deauth, parse_handshake
from .models import DeauthEvent, HandshakeEvent
from .scapy_compat import load_scapy


@dataclass(slots=True)
class DeauthStats:
    threshold: int
    window_seconds: int
    total: int = 0
    by_bssid: Counter[str] = field(default_factory=Counter)
    alerts: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MonitorResult:
    deauth: DeauthStats
    handshakes: list[HandshakeEvent] = field(default_factory=list)


class DeauthFloodDetector:
    def __init__(self, threshold: int = 20, window_seconds: int = 10) -> None:
        self.threshold = threshold
        self.window_seconds = window_seconds
        self._events: deque[tuple[float, DeauthEvent]] = deque()

    def observe(self, event: DeauthEvent) -> str | None:
        now = monotonic()
        self._events.append((now, event))
        while self._events and now - self._events[0][0] > self.window_seconds:
            self._events.popleft()

        count = sum(1 for _, item in self._events if item.bssid == event.bssid)
        if count == self.threshold:
            return f"Possible deauth flood: {count} frames for BSSID {event.bssid} in {self.window_seconds}s"
        return None


def monitor_live(
    iface: str,
    seconds: int,
    deauth_threshold: int = 20,
    deauth_window: int = 10,
) -> MonitorResult:
    scapy = load_scapy()
    detector = DeauthFloodDetector(threshold=deauth_threshold, window_seconds=deauth_window)
    stats = DeauthStats(threshold=deauth_threshold, window_seconds=deauth_window)
    handshakes: list[HandshakeEvent] = []

    def handle(packet) -> None:
        deauth = parse_deauth(packet)
        if deauth:
            stats.total += 1
            stats.by_bssid[deauth.bssid] += 1
            alert = detector.observe(deauth)
            if alert:
                stats.alerts.append(alert)

        handshake = parse_handshake(packet)
        if handshake:
            handshakes.append(handshake)

    scapy["sniff"](iface=iface, prn=handle, timeout=seconds, store=False)
    return MonitorResult(deauth=stats, handshakes=handshakes)


def analyze_packets(packets: Iterable[object]) -> MonitorResult:
    detector = DeauthFloodDetector()
    stats = DeauthStats(threshold=detector.threshold, window_seconds=detector.window_seconds)
    handshakes: list[HandshakeEvent] = []

    for packet in packets:
        deauth = parse_deauth(packet)
        if deauth:
            stats.total += 1
            stats.by_bssid[deauth.bssid] += 1
            alert = detector.observe(deauth)
            if alert:
                stats.alerts.append(alert)

        handshake = parse_handshake(packet)
        if handshake:
            handshakes.append(handshake)

    return MonitorResult(deauth=stats, handshakes=handshakes)


def analyze_pcap(path: str) -> MonitorResult:
    scapy = load_scapy()
    return analyze_packets(scapy["rdpcap"](path))
