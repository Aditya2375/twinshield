import copy
import http.client
import json
import os
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from http.server import ThreadingHTTPServer
from twinshield import detect, fixtures, server, store


class EngineSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, {"TWINSHIELD_HOME": self.temp.name})
        self.env.start()
        self.frames = fixtures.scenario()

    def tearDown(self):
        self.env.stop()
        self.temp.cleanup()

    def ready(self):
        engine = server.Engine(replay=True)
        engine.tick()
        engine.tick()
        return engine

    def test_baseline_needs_two_scans(self):
        engine = server.Engine(replay=True)
        engine.tick()
        self.assertFalse(engine.approve(["CampusNet"])[0])

    def test_observed_baseline_saved_and_reloaded(self):
        engine = self.ready()
        self.assertTrue(engine.approve(["CampusNet"])[0])
        self.assertEqual(set(engine.baseline["networks"]), {"CampusNet"})
        self.assertTrue(detect.valid_baseline(store.load("baseline.json", None)))
        self.assertIsNotNone(server.Engine(replay=True).baseline)

    def test_unknown_and_hidden_names_rejected(self):
        engine = self.ready()
        self.assertFalse(engine.approve(["Not observed"])[0])
        self.assertFalse(engine.approve([""])[0])

    def test_stale_scan_cannot_be_approved(self):
        engine = self.ready()
        engine.last_ok = time.time() - 1000
        self.assertFalse(engine.approve(["CampusNet"])[0])
        self.assertIsNone(engine.baseline)

    def test_error_scan_cannot_be_approved(self):
        engine = self.ready()
        engine.error = "Fixture scanner failure"
        self.assertFalse(engine.approve(["CampusNet"])[0])

    def test_save_failure_keeps_previous_baseline(self):
        engine = self.ready()
        self.assertTrue(engine.approve(["CampusNet"])[0])
        previous = copy.deepcopy(engine.baseline)
        with patch.object(store, "save", side_effect=OSError("Test storage refusal")):
            self.assertFalse(engine.approve(["Hostel-Wifi"])[0])
        self.assertEqual(engine.baseline, previous)

    def test_malformed_baselines_fail_closed(self):
        good = detect.make_baseline(self.frames[:2], {"CampusNet"})
        self.assertTrue(detect.valid_baseline(good))
        variants = [[], {}, {"version": 1, "networks": {"x": None}}]
        for field, value in [
            ("signal_mean", float("nan")),
            ("signal_sd", 0),
            ("channels", ["six"]),
            ("bands", [None]),
        ]:
            broken = copy.deepcopy(good)
            radio = next(iter(broken["networks"]["CampusNet"]["radios"].values()))
            radio[field] = value
            variants.append(broken)
        for value in variants:
            with self.subTest(value=repr(value)):
                store.save("baseline.json", value)
                engine = server.Engine(replay=True)
                self.assertIsNone(engine.baseline)
                engine.tick()
                self.assertEqual(engine.state()["status"], "no_baseline")

    def test_corrupt_local_json_is_not_a_baseline(self):
        (store.home() / "baseline.json").write_text("not json")
        self.assertIsNone(server.Engine(replay=True).baseline)

    def test_scanner_failure_makes_previous_observations_unavailable(self):
        engine = self.ready()
        self.assertTrue(engine.approve(["CampusNet"])[0])
        engine.fx = None
        previous = copy.deepcopy(engine.last_scan)
        with patch.object(
            server.scan,
            "scan_once",
            side_effect=server.scan.ScanError("Fixture scanner failure"),
        ):
            engine.tick()
        self.assertEqual(engine.state()["status"], "unavailable")
        self.assertEqual(engine.last_scan, previous)

    def test_acknowledgment_does_not_change_evidence(self):
        engine = self.ready()
        self.assertTrue(engine.approve(["CampusNet"])[0])
        for _ in range(8):
            engine.tick()
        incident = engine.inc.snapshot()[0]
        old = copy.deepcopy(incident["evidence"])
        engine.ack(incident["key"])
        self.assertTrue(engine.inc.snapshot()[0]["acked"])
        self.assertEqual(engine.inc.snapshot()[0]["evidence"], old)
        self.assertEqual(engine.state()["status"], "alert")


class HTTPBoundary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.env = patch.dict(os.environ, {"TWINSHIELD_HOME": cls.temp.name})
        cls.env.start()
        cls.engine = server.Engine(replay=True)
        cls.engine.tick()
        cls.engine.tick()
        cls.httpd = ThreadingHTTPServer(
            ("127.0.0.1", 0), server.make_handler(cls.engine, 0)
        )
        cls.port = cls.httpd.server_port
        cls.httpd.RequestHandlerClass = server.make_handler(cls.engine, cls.port)
        cls.worker = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.worker.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.worker.join()
        cls.env.stop()
        cls.temp.cleanup()

    def request(self, path, method="GET", body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=6)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            response = conn.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            conn.close()

    def test_local_replay_state(self):
        status, headers, data = self.request("/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(data)["mode"], "replay")
        self.assertEqual(headers["Cache-Control"], "no-store")

    def test_static_assets_and_security_headers(self):
        for path, content_type in [
            ("/", "text/html"),
            ("/app.js", "text/javascript"),
            ("/style.css", "text/css"),
            ("/favicon.svg", "image/svg+xml"),
            ("/assets/manrope-600.ttf", "font/ttf"),
            ("/assets/font-licenses.txt", "text/plain"),
        ]:
            with self.subTest(path=path):
                status, headers, data = self.request(path)
                self.assertEqual(status, 200)
                self.assertTrue(headers["Content-Type"].startswith(content_type))
                self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
                self.assertEqual(headers["X-Frame-Options"], "DENY")
                self.assertTrue(data)

    def test_source_and_private_review_files_not_served(self):
        for path in [
            "/.git/config",
            "/twinshield/store.py",
            "/_review/REVIEW.md",
            "/README.md",
            "/../twinshield/store.py",
        ]:
            with self.subTest(path=path):
                status, _, data = self.request(path)
                self.assertEqual(status, 404)
                self.assertIn(b"Radio silence", data)
                self.assertNotIn(b"import json", data)

    def test_bad_host_rejected_on_reads(self):
        self.assertEqual(
            self.request("/api/state", headers={"Host": "untrusted.invalid"})[0], 403
        )

    def test_cross_origin_write_rejected(self):
        self.assertEqual(
            self.request(
                "/api/ack",
                "POST",
                "{}",
                {
                    "Origin": "https://untrusted.invalid",
                    "Content-Type": "application/json",
                },
            )[0],
            403,
        )

    def test_loopback_alias_is_still_a_distinct_origin(self):
        self.assertEqual(
            self.request(
                "/api/ack",
                "POST",
                "{}",
                {
                    "Origin": f"http://localhost:{self.port}",
                    "Content-Type": "application/json",
                },
            )[0],
            403,
        )

    def test_non_json_write_rejected(self):
        self.assertEqual(
            self.request("/api/ack", "POST", "key=x", {"Content-Type": "text/plain"})[
                0
            ],
            415,
        )

    def test_invalid_and_large_json_rejected(self):
        self.assertEqual(
            self.request("/api/ack", "POST", "{", {"Content-Type": "application/json"})[
                0
            ],
            400,
        )
        self.assertEqual(
            self.request(
                "/api/ack", "POST", "[]", {"Content-Type": "application/json"}
            )[0],
            400,
        )
        self.assertEqual(
            self.request(
                "/api/ack", "POST", "x" * 10001, {"Content-Type": "application/json"}
            )[0],
            413,
        )

    def test_unknown_write_route_rejected(self):
        self.assertEqual(
            self.request(
                "/api/unknown", "POST", "{}", {"Content-Type": "application/json"}
            )[0],
            404,
        )

    def test_approval_validation_rejects_wrong_shape(self):
        self.assertEqual(
            self.request(
                "/api/baseline/approve",
                "POST",
                '{"ssids":"CampusNet"}',
                {"Content-Type": "application/json"},
            )[0],
            400,
        )


if __name__ == "__main__":
    unittest.main()
