"""一键回环实测的启动、错误和资源释放。"""

from pathlib import Path
import sys
from threading import Event
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import local_traffic as demo


class DemoTests(unittest.TestCase):
    def test_rejects_non_loopback_and_honors_early_stop(self):
        stop = Event()
        with patch.object(demo, "capture_live") as capture:
            with self.assertRaises(demo.CaptureError):
                demo.capture_demo("WiFi", stop, Mock())
            stop.set()
            demo.capture_demo("lo", stop, Mock())
            capture.assert_not_called()

    def test_source_failure_releases_every_reserved_endpoint(self):
        opened = []
        original = demo._open_endpoints

        def reserve(*args):
            endpoints = original(*args)
            opened.extend((endpoints.server.socket, endpoints.client, endpoints.receiver, endpoints.sender))
            return endpoints

        with patch.object(demo, "_open_endpoints", side_effect=reserve), \
             patch.object(demo, "capture_live", side_effect=demo.CaptureError("driver error")), \
             patch.object(demo, "_exchange") as exchange:
            with self.assertRaisesRegex(demo.CaptureError, "driver error"):
                demo.capture_demo("lo", Event(), Mock())
            exchange.assert_not_called()
        self.assertEqual(len(opened), 8)
        self.assertTrue(all(sock.fileno() == -1 for sock in opened))


if __name__ == "__main__":
    unittest.main()
