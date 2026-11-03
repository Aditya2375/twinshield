import json, threading, time, pathlib, sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from . import detect, scan, store, fixtures

WEB = pathlib.Path(__file__).resolve().parent.parent
MIME = {".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".json": "application/json"}

class Engine:
    def __init__(self, interval=10, replay=False):
        self.interval, self.replay = max(5,min(3600,interval)), replay
        self.lock = threading.Lock()
        self.baseline = store.load("baseline.json", None)
        self.inc = detect.Incidents()
        self.last_scan, self.error, self.cycle, self.last_ok = [], None, 0, None
        self.recent = []                      # recent raw scans, used to build a baseline on approval
        self.log = store.load("log.json", [])
        if not isinstance(self.log,list): self.log=[]
        if not isinstance(self.baseline,dict) or not isinstance(self.baseline.get("networks"),dict): self.baseline=None
        self.fx = fixtures.scenario() if replay else None
    def tick(self):
        try:
            aps = self.fx[self.cycle % len(self.fx)] if self.fx else scan.scan_once()
            err = None
        except (scan.ScanError, ValueError, TypeError, KeyError) as e:
            aps, err = [], str(e)
        with self.lock:
            self.cycle += 1
            self.error = err
            if err: return
            self.last_scan, self.last_ok = aps, time.time()
            self.recent = (self.recent + [aps])[-6:]
            if self.baseline:
                found = detect.evaluate(aps, self.baseline)
                self.inc.update(found)
                for it in self.inc.items.values():
                    if it["level"] != "low" and it["sightings"] == 1 and it["active"]:
                        self.log.append({"t": time.time(), "key": it["key"], "score": it["score"], "baseline": self.baseline["version"]})
                self.log = self.log[-500:]
                try: store.save("log.json", self.log)
                except OSError: self.error="Could not save the local alert log."
    def loop(self):
        while True:
            self.tick(); time.sleep(self.interval)
    def state(self):
        with self.lock:
            stale = self.last_ok is None or time.time() - self.last_ok > self.interval * 3
            if self.error or stale: status = "unavailable"
            elif not self.baseline: status = "no_baseline"
            elif any(i["active"] and i["level"] == "high" for i in self.inc.items.values()): status = "alert"
            elif any(i["active"] and i["level"] == "review" for i in self.inc.items.values()): status = "review"
            else: status = "clear"
            ssids = sorted({a["ssid"] for a in self.last_scan if a["ssid"]})
            return {"mode": "replay" if self.replay else "live", "status": status, "error": self.error,
                    "cycle": self.cycle, "interval": self.interval, "last_scan_at": self.last_ok,
                    "scan": self.last_scan, "ssids": ssids, "baseline": self.baseline,
                    "incidents": self.inc.snapshot(), "log_size": len(self.log)}
    def approve(self, ssids):
        with self.lock:
            if len(self.recent) < 2: return False, "Need at least two completed scans first."
            if not ssids or any(s not in {a["ssid"] for rows in self.recent for a in rows} for s in ssids): return False,"Choose observed networks only."
            candidate=detect.make_baseline(self.recent,set(ssids))
            try: store.save("baseline.json",candidate)
            except OSError: return False,"Baseline was not saved. Check local storage permissions."
            self.baseline=candidate
            self.inc = detect.Incidents()
            return True, "ok"
    def ack(self, key):
        with self.lock:
            if key in self.inc.items: self.inc.items[key]["acked"] = True

def make_handler(engine, port):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def _json(self, code, obj):
            b = json.dumps(obj).encode()
            self.send_response(code); self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store"); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
        def _allowed_host(self):
            return self.headers.get("Host", "") in (f"127.0.0.1:{port}",f"localhost:{port}")
        def end_headers(self):
            self.send_header("X-Content-Type-Options","nosniff")
            self.send_header("Referrer-Policy","no-referrer")
            self.send_header("X-Frame-Options","DENY")
            super().end_headers()
        def do_GET(self):
            if not self._allowed_host(): return self._json(403,{"error":"forbidden"})
            p = self.path.split("?")[0]
            if p == "/api/state": return self._json(200, engine.state())
            if p == "/": p = "/index.html"
            f = (WEB / p.lstrip("/")).resolve()
            allowed={"index.html","app.js","style.css","demo.json","404.html","robots.txt","sitemap.xml","llms.txt"}
            if WEB not in f.parents or not f.is_file() or f.suffix not in MIME or (f.relative_to(WEB).as_posix() not in allowed and not (f.parent==WEB/"assets" and f.suffix in (".css",".txt"))):
                self.send_response(404); self.end_headers(); return
            b = f.read_bytes()
            self.send_response(200); self.send_header("Content-Type", MIME[f.suffix]); self.send_header("Content-Length", str(len(b)))
            self.end_headers(); self.wfile.write(b)
        def do_POST(self):
            host = self.headers.get("Host", "")
            origin = self.headers.get("Origin", "")
            if host not in (f"127.0.0.1:{port}", f"localhost:{port}") or (origin and origin not in (f"http://127.0.0.1:{port}", f"http://localhost:{port}")):
                return self._json(403, {"error": "forbidden"})
            if not self.headers.get("Content-Type","").startswith("application/json"): return self._json(415,{"error":"JSON required"})
            try: n=int(self.headers.get("Content-Length","0"))
            except ValueError: return self._json(400,{"error":"bad length"})
            if n<0 or n>10000: return self._json(413,{"error":"body too large"})
            self.connection.settimeout(5)
            try: body = json.loads(self.rfile.read(n) or b"{}")
            except (ValueError,OSError): return self._json(400, {"error": "bad json"})
            if not isinstance(body,dict): return self._json(400,{"error":"object required"})
            if self.path == "/api/baseline/approve":
                ssids=body.get("ssids",[])
                if not isinstance(ssids,list) or len(ssids)>100 or any(not isinstance(s,str) or len(s)>128 for s in ssids): return self._json(400,{"error":"invalid network list"})
                ok, msg = engine.approve(ssids)
                return self._json(200 if ok else 409, {"ok": ok, "message": msg})
            if self.path == "/api/ack":
                engine.ack(str(body.get("key", ""))); return self._json(200, {"ok": True})
            self._json(404, {"error": "not found"})
    return H

def serve(port=8787, interval=10, replay=False):
    eng = Engine(interval, replay)
    threading.Thread(target=eng.loop, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", port), make_handler(eng, port))
    print(f"TwinShield dashboard: http://127.0.0.1:{port}  ({'REPLAY of a labelled test fixture' if replay else 'live Wi-Fi scan'})")
    try: srv.serve_forever()
    except KeyboardInterrupt: print()
