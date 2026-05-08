from __future__ import annotations

from dataclasses import dataclass, field
from time import time


def normalize_mac(value: str | None) -> str:
    return (value or "").strip().lower()


@dataclass(slots=True)
class AccessPoint:
    ssid: str
    bssid: str
    channel: int | None = None
    signal_dbm: int | None = None
    crypto: set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time)
    last_seen: float = field(default_factory=time)
    frames: int = 0

    def update(
        self,
        *,
        ssid: str | None = None,
        channel: int | None = None,
        signal_dbm: int | None = None,
        crypto: set[str] | None = None,
    ) -> None:
        if ssid:
            self.ssid = ssid
        if channel is not None:
            self.channel = channel
        if signal_dbm is not None:
            self.signal_dbm = signal_dbm
        if crypto:
            self.crypto.update(crypto)
        self.frames += 1
        self.last_seen = time()

    def as_dict(self) -> dict[str, object]:
        return {
            "ssid": self.ssid,
            "bssid": self.bssid,
            "channel": self.channel,
            "signal_dbm": self.signal_dbm,
            "crypto": sorted(self.crypto),
            "frames": self.frames,
        }


@dataclass(frozen=True, slots=True)
class DeauthEvent:
    source: str
    destination: str
    bssid: str
    reason: int | None
    timestamp: float


@dataclass(frozen=True, slots=True)
class HandshakeEvent:
    source: str
    destination: str
    bssid: str | None
    timestamp: float
    message_hint: str


@dataclass(frozen=True, slots=True)
class RogueFinding:
    severity: str
    bssid: str
    ssid: str
    reason: str
