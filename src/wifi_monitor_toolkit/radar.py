from __future__ import annotations

from .models import AccessPoint
from .scanner import collect_access_points


def build_radar(aps: list[AccessPoint]) -> dict[str, object]:
    buckets = {
        "near": [],
        "mid": [],
        "far": [],
        "unknown": [],
    }

    for ap in sorted(aps, key=lambda item: item.signal_dbm if item.signal_dbm is not None else -999, reverse=True):
        item = ap.as_dict()
        if ap.signal_dbm is None:
            buckets["unknown"].append(item)
        elif ap.signal_dbm >= -55:
            buckets["near"].append(item)
        elif ap.signal_dbm >= -75:
            buckets["mid"].append(item)
        else:
            buckets["far"].append(item)

    return {
        "note": "Radar is based on signal strength, not true physical direction.",
        "counts": {name: len(values) for name, values in buckets.items()},
        "buckets": buckets,
        "display": render_radar(buckets),
    }


def scan_radar(iface: str, seconds: int) -> dict[str, object]:
    aps = collect_access_points(iface, seconds)
    return build_radar(list(aps.values()))


def render_radar(buckets: dict[str, list[dict[str, object]]]) -> str:
    lines = [
        "WiFi Radar (signal-strength map)",
        "",
        "[ NEAR ]",
        *_format_bucket(buckets["near"]),
        "",
        "[ MID  ]",
        *_format_bucket(buckets["mid"]),
        "",
        "[ FAR  ]",
        *_format_bucket(buckets["far"]),
        "",
        "[ UNKNOWN SIGNAL ]",
        *_format_bucket(buckets["unknown"]),
    ]
    return "\n".join(lines)


def _format_bucket(items: list[dict[str, object]]) -> list[str]:
    if not items:
        return ["  none"]
    return [
        f"  {item['ssid']}  {item['bssid']}  ch={item['channel']}  signal={item['signal_dbm']}  crypto={','.join(item['crypto'])}"
        for item in items
    ]
