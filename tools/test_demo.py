"""HTTP checks for the presentation server; no hardware or wireless activity."""

import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

from demo import DemoHandler, ThreadingHTTPServer


class DemoServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DemoHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def test_demo_query_serves_dashboard(self):
        with urlopen(self.base + "/?demo=1", timeout=3) as response:
            self.assertIn(b"startDemoMode", response.read())
            self.assertEqual(response.headers["Cache-Control"], "no-store")

    def test_health_identifies_synthetic_mode(self):
        with urlopen(self.base + "/health", timeout=3) as response:
            self.assertEqual(json.load(response)["mode"], "synthetic")

    def test_source_files_and_relay_are_not_served(self):
        for path in ("/cloud_relay_server.py", "/../README.md", "/ws", "/api/snapshot"):
            with self.assertRaises(HTTPError) as error:
                urlopen(self.base + path, timeout=3)
            self.assertEqual(error.exception.code, 404)
            error.exception.close()


if __name__ == "__main__":
    unittest.main()
