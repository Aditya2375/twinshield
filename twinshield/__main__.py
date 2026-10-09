import argparse, json, sys
from . import server, scan, detect, fixtures

def main():
    ap = argparse.ArgumentParser(prog="twinshield", description="Warn about lookalike Wi-Fi hotspots. Reads access-point metadata only.")
    sub = ap.add_subparsers(dest="cmd")
    s = sub.add_parser("serve", help="scan and serve the local dashboard (default)")
    s.add_argument("--port", type=int, default=8787); s.add_argument("--interval", type=int, default=10)
    s.add_argument("--replay", action="store_true", help="replay a labelled test fixture instead of scanning")
    sub.add_parser("scan", help="print one scan as JSON")
    d = sub.add_parser("demo-data", help="write the dashboard's demo.json from the test fixture")
    d.add_argument("--out", default="demo.json")
    a = ap.parse_args()
    if a.cmd == "scan":
        try: print(json.dumps(scan.scan_once(), indent=1))
        except scan.ScanError as e: print("Scan failed:", e, file=sys.stderr); sys.exit(1)
    elif a.cmd == "demo-data":
        cyc = fixtures.scenario(); base = detect.make_baseline(cyc[:6], {"CampusNet", "CampusNet-Guest", "Hostel-Wifi"})
        inc = detect.Incidents(); frames = []
        for i, aps in enumerate(cyc):
            inc.update(detect.evaluate(aps, base), now=1000 + i * 10)
            frames.append({"cycle": i + 1, "scan": aps, "incidents": json.loads(json.dumps(inc.snapshot()))})
        json.dump({"fixture": True, "interval": 10, "baseline": base, "frames": frames}, open(a.out, "w"), indent=1)
        print("wrote", a.out)
    else:
        server.serve(getattr(a, "port", 8787), getattr(a, "interval", 10), getattr(a, "replay", False))
main()
