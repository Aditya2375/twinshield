"""Read nearby access points. Metadata only: no packets, no credentials, no deauth."""
import platform, re, shutil, subprocess

class ScanError(Exception):
    pass

def _rank_security(s):
    s = (s or "").upper()
    if not s or s in ("--", "OPEN", "NONE"):
        return "OPEN"
    if "WPA3" in s or "SAE" in s:
        return "WPA3"
    if "WPA2" in s or "RSN" in s:
        return "WPA2"
    if "WPA" in s:
        return "WPA"
    if "WEP" in s:
        return "WEP"
    return s

def _split_nmcli(line):
    out, cur, esc = [], "", False
    for ch in line:
        if esc:
            cur += ch; esc = False
        elif ch == "\\":
            esc = True
        elif ch == ":":
            out.append(cur); cur = ""
        else:
            cur += ch
    out.append(cur)
    return out

def parse_nmcli(text):
    aps = []
    for line in text.splitlines():
        f = _split_nmcli(line)
        if len(f) < 6:
            continue
        ssid, bssid, chan, freq, signal, sec = f[:6]
        if not re.fullmatch(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}", bssid):
            continue
        aps.append({"ssid": ssid, "bssid": bssid.lower(), "channel": int(chan or 0),
                    "freq": int(re.sub(r"\D", "", freq) or 0),
                    "signal_pct": int(signal or 0), "security": _rank_security(sec)})
    return aps

def parse_netsh(text):
    aps, ssid, sec = [], "", ""
    cur = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"SSID \d+ : (.*)", line)
        if m:
            ssid = m.group(1); continue
        m = re.match(r"Authentication\s*: (.*)", line)
        if m:
            sec = _rank_security(m.group(1)); continue
        m = re.match(r"BSSID \d+\s*: (.*)", line)
        if m:
            cur = {"ssid": ssid, "bssid": m.group(1).lower(), "channel": 0, "freq": 0, "signal_pct": 0, "security": sec}
            aps.append(cur); continue
        if cur is not None:
            m = re.match(r"Signal\s*: (\d+)%", line)
            if m: cur["signal_pct"] = int(m.group(1))
            m = re.match(r"Channel\s*: (\d+)", line)
            if m: cur["channel"] = int(m.group(1))
    return aps

def parse_airport(text):
    aps = []
    for line in text.splitlines()[1:]:
        m = re.match(r"\s*(.*?)\s+((?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})\s+(-\d+)\s+(\d+)[,\d]*\s+\S+\s+\S+\s+(.*)$", line, re.I)
        if m:
            ssid, bssid, rssi, chan, sec = m.groups()
            bssid = ":".join(p.zfill(2) for p in bssid.split(":")).lower()
            aps.append({"ssid": ssid, "bssid": bssid, "channel": int(chan), "freq": 0,
                        "signal_pct": max(0, min(100, 2 * (int(rssi) + 100))), "security": _rank_security(sec)})
    return aps

def scan_once():
    sysname = platform.system()
    try:
        if sysname == "Linux":
            if not shutil.which("nmcli"):
                raise ScanError("nmcli (NetworkManager) was not found on this machine.")
            subprocess.run(["nmcli", "device", "wifi", "rescan"], capture_output=True, timeout=15)
            r = subprocess.run(["nmcli", "-t", "-f", "SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY", "device", "wifi", "list"],
                               capture_output=True, text=True, timeout=20)
            if r.returncode != 0:
                raise ScanError(r.stderr.strip() or "nmcli failed")
            return parse_nmcli(r.stdout.replace("\\:", "\\:"))
        if sysname == "Windows":
            r = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True, timeout=20)
            if r.returncode != 0:
                raise ScanError("netsh could not read Wi-Fi networks.")
            return parse_netsh(r.stdout)
        if sysname == "Darwin":
            path = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"
            r = subprocess.run([path, "-s"], capture_output=True, text=True, timeout=20)
            if r.returncode != 0 or not r.stdout.strip():
                raise ScanError("macOS no longer provides a Wi-Fi scan tool on this version. Use --replay or a Linux machine.")
            return parse_airport(r.stdout)
    except subprocess.TimeoutExpired:
        raise ScanError("The Wi-Fi scan timed out.")
    except OSError as e:
        raise ScanError(str(e))
    raise ScanError(f"Scanning is not supported on {sysname}.")
