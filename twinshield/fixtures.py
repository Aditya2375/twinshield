"""Recorded-style test scenario for logic tests and the public demo. Labelled as a fixture everywhere it is shown."""
import random

def scenario(cycles=24, seed=7):
    rnd = random.Random(seed)
    base = [
        ("CampusNet", "a4:2b:b0:11:c0:01", 36, 5180, 74, "WPA2"),
        ("CampusNet", "a4:2b:b0:11:c0:02", 6, 2437, 66, "WPA2"),
        ("CampusNet", "a4:2b:b0:11:c0:03", 149, 5745, 58, "WPA2"),
        ("CampusNet-Guest", "a4:2b:b0:11:d0:01", 1, 2412, 52, "WPA2"),
        ("Hostel-Wifi", "f0:9f:c2:5a:77:10", 11, 2462, 61, "WPA2"),
        ("PrinterRoom", "10:62:eb:00:9c:42", 6, 2437, 38, "WPA2"),
        ("Cafe Beans", "3c:84:6a:9e:21:b8", 44, 5220, 47, "OPEN"),
    ]
    cyc = []
    for i in range(cycles):
        scan = []
        for ssid, b, ch, fr, sg, sec in base:
            if ssid == "CampusNet" and b.endswith("02") and 12 <= i < 24:
                ch, fr = 11, 2462          # ordinary channel change by the owner
            if rnd.random() < 0.04 and ssid in ("PrinterRoom", "Cafe Beans"):
                continue
            scan.append({"ssid": ssid, "bssid": b, "channel": ch, "freq": fr,
                         "signal_pct": max(5, min(99, sg + rnd.randint(-4, 4))), "security": sec})
        if i >= 8:   # controlled twin: same name, new radio, no security
            scan.append({"ssid": "CampusNet", "bssid": "02:19:e3:5d:44:aa", "channel": 6, "freq": 2437,
                         "signal_pct": 88 + rnd.randint(-3, 3), "security": "OPEN"})
        if i >= 16:  # look-alike spelling
            scan.append({"ssid": "CampusNet-", "bssid": "02:19:e3:5d:44:b1", "channel": 1, "freq": 2412,
                         "signal_pct": 71 + rnd.randint(-3, 3), "security": "WPA"})
        cyc.append(scan)
    return cyc
