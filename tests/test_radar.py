from wifi_monitor_toolkit.models import AccessPoint
from wifi_monitor_toolkit.radar import build_radar


def test_radar_buckets_access_points_by_signal_strength():
    result = build_radar(
        [
            AccessPoint(ssid="Near", bssid="00:00:00:00:00:01", signal_dbm=-40),
            AccessPoint(ssid="Mid", bssid="00:00:00:00:00:02", signal_dbm=-65),
            AccessPoint(ssid="Far", bssid="00:00:00:00:00:03", signal_dbm=-85),
            AccessPoint(ssid="Unknown", bssid="00:00:00:00:00:04", signal_dbm=None),
        ]
    )

    assert result["counts"] == {"near": 1, "mid": 1, "far": 1, "unknown": 1}
    assert "WiFi Radar" in result["display"]
