from wifi_monitor_toolkit.models import AccessPoint
from wifi_monitor_toolkit.rogue import find_rogues


def test_unknown_bssid_reusing_trusted_ssid_is_high_severity():
    trusted = {
        "aa:bb:cc:dd:ee:ff": AccessPoint(
            ssid="LabNet",
            bssid="aa:bb:cc:dd:ee:ff",
            channel=6,
            crypto={"WPA2"},
        )
    }
    observed = {
        "11:22:33:44:55:66": AccessPoint(
            ssid="LabNet",
            bssid="11:22:33:44:55:66",
            channel=6,
            crypto={"WPA2"},
        )
    }

    findings = find_rogues(observed, trusted)

    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "trusted SSID" in findings[0].reason


def test_known_bssid_channel_change_is_reported():
    trusted = {
        "aa:bb:cc:dd:ee:ff": AccessPoint(
            ssid="LabNet",
            bssid="aa:bb:cc:dd:ee:ff",
            channel=6,
            crypto={"WPA2"},
        )
    }
    observed = {
        "aa:bb:cc:dd:ee:ff": AccessPoint(
            ssid="LabNet",
            bssid="aa:bb:cc:dd:ee:ff",
            channel=11,
            crypto={"WPA2"},
        )
    }

    findings = find_rogues(observed, trusted)

    assert len(findings) == 1
    assert findings[0].severity == "low"
    assert "changed channel" in findings[0].reason
