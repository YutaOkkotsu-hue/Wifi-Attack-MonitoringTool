# WiFi Attack & Monitoring Toolkit

Legal lab use only. This toolkit observes WiFi management/data traffic and reports suspicious activity such as deauthentication floods, handshake activity, and rogue access points. It does not perform attacks, send packets, crack passwords, or bypass access controls.

## Features

- Detect nearby access points from beacon and probe response frames
- Monitor deauthentication packets in real time
- Detect WPA handshake activity from live traffic or `.pcap` files
- Detect rogue APs by comparing observed APs against a trusted inventory
- WiFi radar-style signal map for nearby APs
- Local JSON HTTP API for lab dashboards and integrations
- Optional `aircrack-ng` integration for capture/handshake validation only

## Requirements

- Linux
- Python 3.10+
- Wireless adapter that supports monitor mode
- Root privileges for live packet capture
- Optional: `aircrack-ng`

## Install

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Prepare Monitor Mode

Use your own lab interface and follow local laws. One common lab setup is:

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

Some adapters expose a separate monitor interface such as `wlan0mon`.

## Usage

Scan nearby APs:

```bash
sudo python -m wifi_monitor_toolkit scan --iface wlan0mon --seconds 30
```

Monitor for deauth packets and handshakes:

```bash
sudo python -m wifi_monitor_toolkit monitor --iface wlan0mon --seconds 120
```

Analyze an existing capture:

```bash
python -m wifi_monitor_toolkit analyze capture.pcap
```

Show a signal-strength radar map:

```bash
sudo python -m wifi_monitor_toolkit radar --iface wlan0mon --seconds 30
```

Check for rogue APs from a trusted inventory:

```bash
sudo python -m wifi_monitor_toolkit rogue --iface wlan0mon --trusted trusted_aps.example.json --seconds 60
```

Optional aircrack-ng validation:

```bash
python -m wifi_monitor_toolkit aircrack-check capture.pcap
```

Start the local API:

```bash
sudo python -m wifi_monitor_toolkit serve-api --host 127.0.0.1 --port 8080
```

API endpoints:

- `GET /health`
- `GET /scan?iface=wlan0mon&seconds=10`
- `GET /radar?iface=wlan0mon&seconds=10`
- `GET /monitor?iface=wlan0mon&seconds=10`
- `GET /rogue?iface=wlan0mon&trusted=trusted_aps.example.json&seconds=10`

## Trusted AP Inventory

Create a JSON file containing trusted AP definitions:

```json
[
  {
    "ssid": "LabNet",
    "bssid": "aa:bb:cc:dd:ee:ff",
    "channel": 6,
    "crypto": ["WPA2"]
  }
]
```

The rogue detector reports:

- Unknown BSSID broadcasting an existing trusted SSID
- Known BSSID using a changed SSID
- Known BSSID using a changed channel
- Known BSSID using changed crypto metadata when it can be inferred

## Notes

- Live capture depends on monitor-mode support and local driver behavior.
- The radar view is based on signal strength. A single normal WiFi adapter cannot provide true physical direction.
- Channel hopping is intentionally left outside the default capture loop. For lab use, set the interface channel with `iw` or run a controlled channel-hopping script you understand.
- This project is defensive monitoring software. It intentionally does not crack passwords or perform attacks. Do not use it on networks you do not own or have explicit permission to test.
