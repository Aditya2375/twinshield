"""Rule-based evidence scoring. A score is a review priority, not the chance of an attack."""
import statistics, time

SEC_RANK = {"OPEN": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA3": 4}

def band(ap):
    f = ap.get("freq", 0); c = ap.get("channel", 0)
    if f:
        return "6 GHz" if f >= 5925 else "5 GHz" if f >= 4900 else "2.4 GHz"
    return "5 GHz" if c > 14 else "2.4 GHz"

def _norm(s):
    return "".join(ch for ch in s.lower() if ch.isalnum())

def lookalike(a, b):
    """True when two different names are one small edit apart after ignoring case and punctuation."""
    if a == b: return False
    x, y = _norm(a), _norm(b)
    if x == y: return True
    if abs(len(x) - len(y)) > 1 or len(x) < 4: return False
    return _edit1(x, y)

def _edit1(x, y):
    if len(x) == len(y):
        return sum(p != q for p, q in zip(x, y)) == 1
    if len(x) > len(y): x, y = y, x
    i = j = d = 0
    while i < len(x) and j < len(y):
        if x[i] == y[j]: i += 1; j += 1
        else:
            d += 1; j += 1
            if d > 1: return False
    return True

def make_baseline(aps, ssids=None, name="baseline"):
    """Build an owner-approved baseline from one or more scans (list of AP lists)."""
    nets = {}
    for scan in aps:
        for ap in scan:
            if ssids is not None and ap["ssid"] not in ssids: continue
            if not ap["ssid"]: continue
            n = nets.setdefault(ap["ssid"], {"security": ap["security"], "radios": {}})
            if SEC_RANK.get(ap["security"], 0) > SEC_RANK.get(n["security"], 0): n["security"] = ap["security"]
            r = n["radios"].setdefault(ap["bssid"], {"channels": [], "bands": [], "signals": [], "security": ap["security"]})
            if ap["channel"] not in r["channels"]: r["channels"].append(ap["channel"])
            if band(ap) not in r["bands"]: r["bands"].append(band(ap))
            r["signals"].append(ap["signal_pct"])
    for n in nets.values():
        for r in n["radios"].values():
            s = r.pop("signals")
            r["signal_mean"] = round(statistics.mean(s), 1)
            r["signal_sd"] = round(max(statistics.pstdev(s), 5.0), 1)
    return {"name": name, "version": int(time.time()), "networks": nets}

def evaluate(scan, baseline):
    """Return findings for one scan: list of dicts with evidence and a 0-100 review score."""
    out = []
    nets = baseline.get("networks", {})
    for ap in scan:
        ssid = ap["ssid"]
        ev, score = [], 0
        known = nets.get(ssid)
        kind = None
        if known:
            r = known["radios"].get(ap["bssid"])
            if r is None:
                kind = "unfamiliar_radio"
                score += 45
                ev.append({"rule": "Unfamiliar radio using a known name", "points": 45,
                           "detail": f'"{ssid}" is approved, but radio {ap["bssid"]} is not in the baseline. The baseline lists {len(known["radios"])} approved radio(s).'})
                if SEC_RANK.get(ap["security"], 0) < SEC_RANK.get(known["security"], 0):
                    score += 35
                    ev.append({"rule": "Weaker security than the approved network", "points": 35,
                               "detail": f'Advertises {ap["security"]}; the approved network uses {known["security"]}.'})
                stronger = [x for x in known["radios"].values()]
                if stronger:
                    top = max(x["signal_mean"] for x in stronger)
                    if ap["signal_pct"] >= top + 15:
                        score += 10
                        ev.append({"rule": "Much stronger than every approved radio", "points": 10,
                                   "detail": f'Signal {ap["signal_pct"]}% vs the strongest approved radio near {round(top)}%.'})
            else:
                kind = "known_radio_changed"
                if SEC_RANK.get(ap["security"], 0) < SEC_RANK.get(r["security"], 0):
                    score += 50
                    ev.append({"rule": "Security downgrade on an approved radio", "points": 50,
                               "detail": f'Approved radio {ap["bssid"]} used {r["security"]} and now advertises {ap["security"]}. This can mean a copied radio address.'})
                if ap["channel"] not in r["channels"]:
                    score += 12
                    ev.append({"rule": "Channel not seen for this radio", "points": 12,
                               "detail": f'Now on channel {ap["channel"]}; baseline channels: {", ".join(map(str, r["channels"]))}. Channel changes are often normal.'})
                if band(ap) not in r["bands"]:
                    score += 12
                    ev.append({"rule": "Band not seen for this radio", "points": 12,
                               "detail": f'Now on {band(ap)}; baseline: {", ".join(r["bands"])}.'})
                z = abs(ap["signal_pct"] - r["signal_mean"]) / r["signal_sd"]
                if z > 3:
                    score += 8
                    ev.append({"rule": "Unusual signal strength", "points": 8,
                               "detail": f'Signal {ap["signal_pct"]}% is {z:.1f} deviations from the usual {r["signal_mean"]}%. People and walls move signal, so this is weak evidence alone.'})
        else:
            for k in nets:
                if lookalike(ssid, k):
                    kind = "lookalike_name"
                    score += 30
                    ev.append({"rule": "Name is one small edit from an approved network", "points": 30,
                               "detail": f'"{ssid}" looks like approved network "{k}".'})
                    if SEC_RANK.get(ap["security"], 0) < SEC_RANK.get(nets[k]["security"], 0):
                        score += 25
                        ev.append({"rule": "Weaker security than the lookalike target", "points": 25,
                                   "detail": f'Advertises {ap["security"]}; "{k}" uses {nets[k]["security"]}.'})
                    break
        if score:
            out.append({"key": f'{ssid}|{ap["bssid"]}', "ssid": ssid, "bssid": ap["bssid"], "kind": kind,
                        "channel": ap["channel"], "band": band(ap), "security": ap["security"],
                        "signal_pct": ap["signal_pct"], "evidence": ev, "score": min(score, 100)})
    return out

def level(score, sightings):
    if score >= 60 and sightings >= 2: return "high"
    if score >= 30: return "review"
    return "low"

LABEL = {"high": "Strong suspicious evidence", "review": "Review", "low": "Low"}

class Incidents:
    """Fold repeated sightings into one incident per (name, radio)."""
    def __init__(self):
        self.items = {}
    def update(self, findings, now=None):
        now = now or time.time()
        seen = set()
        for f in findings:
            seen.add(f["key"])
            it = self.items.get(f["key"])
            if not it:
                it = dict(f, first_seen=now, sightings=0, acked=False, signal_history=[])
                self.items[f["key"]] = it
            it.update({k: f[k] for k in ("channel", "band", "security", "signal_pct", "evidence", "score", "kind")})
            it["sightings"] += 1; it["last_seen"] = now; it["active"] = True
            it["signal_history"] = (it["signal_history"] + [f["signal_pct"]])[-40:]
            it["level"] = level(it["score"], it["sightings"]); it["label"] = LABEL[it["level"]]
        for k, it in self.items.items():
            if k not in seen: it["active"] = False
        return self
    def snapshot(self):
        return sorted(self.items.values(), key=lambda i: (not i["active"], -i["score"]))
