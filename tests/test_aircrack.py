from wifi_monitor_toolkit.aircrack import _compact_output


def test_compact_output_keeps_handshake_lines():
    output = """
    random line
    BSSID              ESSID
    WPA (1 handshake)
    another line
    """

    compacted = _compact_output(output)

    assert "BSSID" in compacted
    assert "handshake" in compacted
