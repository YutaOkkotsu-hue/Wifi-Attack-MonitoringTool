from __future__ import annotations

import json
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .detectors import monitor_live
from .radar import scan_radar
from .rogue import scan_for_rogues
from .scanner import collect_access_points, summarize_aps


class ToolkitApiHandler(BaseHTTPRequestHandler):
    server_version = "WifiMonitorToolkitAPI/0.1"

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)

        try:
            if parsed.path == "/health":
                self._send_json({"status": "ok"})
                return

            if parsed.path == "/scan":
                iface = _required(query, "iface")
                seconds = _int_query(query, "seconds", 10)
                aps = collect_access_points(iface, seconds)
                self._send_json(summarize_aps(aps.values()))
                return

            if parsed.path == "/radar":
                iface = _required(query, "iface")
                seconds = _int_query(query, "seconds", 10)
                self._send_json(scan_radar(iface, seconds))
                return

            if parsed.path == "/monitor":
                iface = _required(query, "iface")
                seconds = _int_query(query, "seconds", 10)
                result = monitor_live(iface, seconds)
                self._send_json(
                    {
                        "deauth": {
                            "total": result.deauth.total,
                            "by_bssid": dict(result.deauth.by_bssid),
                            "alerts": result.deauth.alerts,
                        },
                        "handshakes": [asdict(event) for event in result.handshakes],
                    }
                )
                return

            if parsed.path == "/rogue":
                iface = _required(query, "iface")
                trusted = _required(query, "trusted")
                seconds = _int_query(query, "seconds", 10)
                self._send_json([asdict(item) for item in scan_for_rogues(iface, trusted, seconds)])
                return

            self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
        except ValueError as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.INTERNAL_SERVER_ERROR)

    def log_message(self, fmt: str, *args: object) -> None:
        print(f"{self.address_string()} - {fmt % args}")

    def _send_json(self, value: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        payload = json.dumps(value, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def serve(host: str, port: int) -> None:
    server = ThreadingHTTPServer((host, port), ToolkitApiHandler)
    print(f"WiFi Monitor Toolkit API listening on http://{host}:{port}")
    server.serve_forever()


def _required(query: dict[str, list[str]], name: str) -> str:
    value = query.get(name, [""])[0].strip()
    if not value:
        raise ValueError(f"missing required query parameter: {name}")
    return value


def _int_query(query: dict[str, list[str]], name: str, default: int) -> int:
    raw = query.get(name, [str(default)])[0]
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value < 1:
        raise ValueError(f"{name} must be greater than 0")
    return value
