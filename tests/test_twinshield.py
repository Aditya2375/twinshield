import unittest
from twinshield import scan, detect, fixtures

NMCLI = r"""HomeNet:AA\:BB\:CC\:DD\:EE\:01:6:2437 MHz:80:WPA2
:AA\:BB\:CC\:DD\:EE\:02:36:5180 MHz:55:WPA2 WPA3
Cafe\: Free:AA\:BB\:CC\:DD\:EE\:03:1:2412 MHz:40:--""".replace(" MHz", "")

class T(unittest.TestCase):
    def test_nmcli(self):
        a = scan.parse_nmcli(NMCLI)
        self.assertEqual(len(a), 3)
        self.assertEqual(a[0]["bssid"], "aa:bb:cc:dd:ee:01"); self.assertEqual(a[0]["security"], "WPA2")
        self.assertEqual(a[1]["security"], "WPA3"); self.assertEqual(a[2]["ssid"], "Cafe: Free"); self.assertEqual(a[2]["security"], "OPEN")
    def test_netsh(self):
        t = "SSID 1 : Lab\n    Authentication          : WPA2-Personal\n    BSSID 1                 : 11:22:33:44:55:66\n         Signal             : 71%\n         Channel            : 6\n"
        a = scan.parse_netsh(t); self.assertEqual((a[0]["ssid"], a[0]["signal_pct"], a[0]["channel"], a[0]["security"]), ("Lab", 71, 6, "WPA2"))
    def test_lookalike(self):
        self.assertTrue(detect.lookalike("CampusNet-", "CampusNet")); self.assertTrue(detect.lookalike("Campus_Net", "CampusNet"))
        self.assertTrue(detect.lookalike("CampusNat", "CampusNet")); self.assertFalse(detect.lookalike("Hostel", "CampusNet"))
    def test_scenario(self):
        cyc = fixtures.scenario(); base = detect.make_baseline(cyc[:6], {"CampusNet", "Hostel-Wifi"})
        self.assertEqual(detect.evaluate(cyc[2], base), [])                      # no false alarm on baseline data
        twin = [f for f in detect.evaluate(cyc[9], base) if f["bssid"] == "02:19:e3:5d:44:aa"]
        self.assertTrue(twin and twin[0]["score"] >= 80)
        moved = [f for f in detect.evaluate(cyc[14], base) if f["bssid"].endswith("c0:02")]
        self.assertTrue(moved and moved[0]["score"] < 30)                         # owner channel change stays low
    def test_incident_levels(self):
        inc = detect.Incidents(); f = [{"key": "k", "ssid": "x", "bssid": "b", "kind": "unfamiliar_radio", "channel": 1, "band": "2.4 GHz", "security": "OPEN", "signal_pct": 80, "evidence": [], "score": 80}]
        inc.update(f); self.assertEqual(inc.snapshot()[0]["level"], "review")    # one sighting is never "strong"
        inc.update(f); self.assertEqual(inc.snapshot()[0]["level"], "high")
        inc.update([]); self.assertFalse(inc.snapshot()[0]["active"])
if __name__ == "__main__": unittest.main()
