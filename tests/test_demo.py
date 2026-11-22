"""一键回环实测的启动、错误和资源释放。"""

import errno
from pathlib import Path
import sys
from threading import Event
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import local_traffic as demo
from capture import read_pcap


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
        self.assertIn(len(opened), (4, 8))
        self.assertTrue(all(sock.fileno() == -1 for sock in opened))

    def test_ipv4_only_capture_verifies_the_available_stack(self):
        sample = Path(__file__).resolve().parents[1] / "验收样例" / "本机回环.pcap"
        channel = demo.Endpoints(Mock(server_port=62045), Mock(), Mock(), Mock())
        channel.client.getsockname.return_value = ("127.0.0.1", 62046)
        channel.receiver.getsockname.return_value = ("127.0.0.1", 58570)
        channel.sender.getsockname.return_value = ("127.0.0.1", 58571)
        unavailable = OSError(errno.EADDRNOTAVAIL, "IPv6 disabled")
        callback = Mock()

        def replay(name, stop, receive, *, capture_filter, on_ready):
            self.assertNotIn("::1", capture_filter)
            self.assertIn("port 58570", capture_filter)
            on_ready()
            with sample.open("rb") as stream:
                read_pcap(stream, stop, receive)

        with patch.object(demo, "_open_endpoints", side_effect=[channel, unavailable]), \
             patch.object(demo, "capture_live", side_effect=replay), \
             patch.object(demo.secrets, "token_hex", return_value="abcdefghijklmnop"), \
             patch.object(demo, "_exchange") as exchange, patch.object(demo, "_marked_pings") as pings:
            status = demo.capture_demo("lo", Event(), callback)
        self.assertEqual(status, "已验证 IPv4，IPv6 回环不可用")
        self.assertEqual(callback.call_count, 17)
        self.assertEqual(exchange.call_count, 1)
        self.assertEqual(list(pings.call_args.args[2]), ["127.0.0.1"])

    def test_socket_failures_are_reported(self):
        unavailable = OSError(errno.EAFNOSUPPORT, "family unavailable")
        denied = PermissionError(errno.EACCES, "denied")
        for error, expected in ((unavailable, demo.CaptureError), (denied, PermissionError)):
            with self.subTest(error=error), patch.object(demo, "_open_endpoints", side_effect=error), \
                 patch.object(demo, "capture_live") as capture, self.assertRaises(expected):
                demo.capture_demo("lo", Event(), Mock())
            capture.assert_not_called()


if __name__ == "__main__":
    unittest.main()
