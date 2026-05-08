from __future__ import annotations

import argparse
import json
from dataclasses import asdict

from .api import serve
from .aircrack import check_capture
from .detectors import analyze_pcap, monitor_live
from .radar import scan_radar
from .rogue import scan_for_rogues
from .scanner import collect_access_points, summarize_aps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="wifi-monitor-toolkit",
        description="Legal lab WiFi monitoring toolkit. Does not transmit attack packets.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Detect nearby access points")
    scan.add_argument("--iface", required=True, help="Monitor-mode wireless interface")
    scan.add_argument("--seconds", type=int, default=30)

    radar = sub.add_parser("radar", help="Show a signal-strength radar map of nearby APs")
    radar.add_argument("--iface", required=True, help="Monitor-mode wireless interface")
    radar.add_argument("--seconds", type=int, default=30)
    radar.add_argument("--json", action="store_true", help="Print radar data as JSON")

    monitor = sub.add_parser("monitor", help="Monitor deauth packets and EAPOL handshakes")
    monitor.add_argument("--iface", required=True, help="Monitor-mode wireless interface")
    monitor.add_argument("--seconds", type=int, default=60)
    monitor.add_argument("--deauth-threshold", type=int, default=20)
    monitor.add_argument("--deauth-window", type=int, default=10)

    analyze = sub.add_parser("analyze", help="Analyze an existing pcap")
    analyze.add_argument("pcap")

    rogue = sub.add_parser("rogue", help="Detect rogue APs against a trusted JSON inventory")
    rogue.add_argument("--iface", required=True, help="Monitor-mode wireless interface")
    rogue.add_argument("--trusted", required=True, help="Path to trusted AP JSON inventory")
    rogue.add_argument("--seconds", type=int, default=60)

    aircrack = sub.add_parser("aircrack-check", help="Validate capture metadata with aircrack-ng")
    aircrack.add_argument("pcap")

    api = sub.add_parser("serve-api", help="Start a local defensive monitoring HTTP API")
    api.add_argument("--host", default="127.0.0.1")
    api.add_argument("--port", type=int, default=8080)

    args = parser.parse_args(argv)

    if args.command == "scan":
        _print_json(summarize_aps(collect_access_points(args.iface, args.seconds).values()))
        return 0

    if args.command == "radar":
        result = scan_radar(args.iface, args.seconds)
        if args.json:
            _print_json(result)
        else:
            print(result["display"])
        return 0

    if args.command == "monitor":
        result = monitor_live(args.iface, args.seconds, args.deauth_threshold, args.deauth_window)
        _print_monitor(result)
        return 0

    if args.command == "analyze":
        _print_monitor(analyze_pcap(args.pcap))
        return 0

    if args.command == "rogue":
        _print_json([asdict(finding) for finding in scan_for_rogues(args.iface, args.trusted, args.seconds)])
        return 0

    if args.command == "aircrack-check":
        result = check_capture(args.pcap)
        _print_json(
            {
                "available": result.available,
                "handshake_seen": result.handshake_seen,
                "summary": result.summary,
            }
        )
        return 0

    if args.command == "serve-api":
        serve(args.host, args.port)
        return 0

    return 2


def _print_monitor(result) -> None:
    _print_json(
        {
            "deauth": {
                "total": result.deauth.total,
                "by_bssid": dict(result.deauth.by_bssid),
                "alerts": result.deauth.alerts,
            },
            "handshakes": [asdict(event) for event in result.handshakes],
        }
    )


def _print_json(value: object) -> None:
    print(json.dumps(value, indent=2, sort_keys=True))
