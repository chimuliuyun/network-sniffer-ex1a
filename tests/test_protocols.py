"""离线边界用例。所有报文只在内存中构造。"""

from ipaddress import ip_address
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from protocols import FlowTracker, parse_packet


def ipv4(proto, payload, reverse=False, fragment=0):
    src, dst = (b"\x7f\x00\x00\x01", b"\x7f\x00\x00\x02")
    if reverse:
        src, dst = dst, src
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 7, fragment,
                       64, proto, 0, src, dst) + payload


def ipv6(proto, payload):
    return struct.pack("!IHBB16s16s", 6 << 28, len(payload), proto, 64,
                       ip_address("::1").packed, ip_address("::2").packed) + payload


def tcp(payload=b"", flags=0x18, seq=17, reverse=False):
    src, dst = (8088, 52001) if reverse else (52001, 8088)
    return struct.pack("!HHIIBBHHH", src, dst, seq, 0, 0x50, flags, 8192, 0, 0) + payload


def ethernet(ether_type, payload):
    return bytes.fromhex("020000000001020000000002") + struct.pack("!H", ether_type) + payload


class ProtocolTests(unittest.TestCase):
    def test_vlan_and_http_off_standard_port(self):
        ip = ipv4(6, tcp(b"GET /demo HTTP/1.1\r\nHost: localhost\r\n\r\n"))
        frame = ethernet(0x88A8, struct.pack("!HHHH", 77, 0x8100, 42, 0x0800) + ip)
        p = parse_packet(1, 1, frame)
        self.assertEqual(p.layers, ("Ethernet", "VLAN", "IPv4", "TCP", "HTTP"))
        for layer in ("IPv4", "tcp", "HTTP", "全部", "All"):
            self.assertTrue(p.matches(layer))
        self.assertFalse(p.matches("UDP"))
        self.assertEqual((p.sport, p.dport, p.details["HTTP 方法"]), (52001, 8088, "GET"))
        self.assertEqual(p.details["VLAN ID（由外到内）"], "77 → 42")
        reply = parse_packet(2, 101, ipv4(6, tcp(b"HTTP/1.1 200 OK\r\n")))
        self.assertEqual(reply.details["HTTP 状态码"], "200")

    def test_http_requires_a_start_line_within_ip_length(self):
        for payload in (b"", b"GET / HTTP/1.1", b"noise\r\nGET / HTTP/1.1\r\n", b"\x16\x03\x03"):
            with self.subTest(payload=payload):
                frame = ethernet(0x0800, ipv4(6, tcp(payload))) + b"GET / HTTP/1.1\r\n"
                self.assertEqual(parse_packet(0, 1, frame).protocol, "TCP")

    def test_loopback_address_families_and_echo(self):
        v4 = ipv4(1, struct.pack("!BBHHH", 8, 0, 0, 27, 11))
        v6 = ipv6(58, struct.pack("!BBHHH", 129, 0, 0, 28, 12))
        for family, link, order, data in [(2, 0, "little", v4), (23, 0, "little", v6),
                                           (30, 0, "big", v6), (28, 108, "big", v6)]:
            with self.subTest(family=family):
                p = parse_packet(1, link, family.to_bytes(4, order) + data)
                self.assertEqual(p.protocol, "ICMP" if family == 2 else "ICMPv6")
                self.assertTrue(p.matches("ICMP"))
                self.assertIn("Echo", p.info)

    def test_ipv6_extensions_and_non_initial_fragment(self):
        udp = struct.pack("!HHHH", 5361, 53, 8, 0)
        extensions = bytes([60, 0]) + bytes(6) + bytes([17, 0]) + bytes(6)
        p = parse_packet(0, 229, ipv6(0, extensions + udp))
        self.assertEqual(p.layers, ("IPv6", "UDP"))
        self.assertEqual((p.src, p.dport, p.details["IPv6 扩展首部类型"]), ("::1", 53, "0 → 60"))
        later = struct.pack("!BBHI", 6, 0, 8, 1234) + tcp()
        p = parse_packet(0, 101, ipv6(44, later))
        self.assertEqual(p.protocol, "IPv6")
        self.assertIsNone(p.sport)
        self.assertEqual(p.details["分片偏移（字节）"], "8")
        p = parse_packet(0, 101, ipv4(6, tcp(), fragment=1))
        self.assertEqual(p.protocol, "IPv4")
        self.assertIsNone(FlowTracker().add(p))

    def test_short_and_damaged_headers_never_escape_parser(self):
        complete = ethernet(0x0800, ipv4(6, tcp(b"GET / HTTP/1.1\r\n")))
        for length in range(len(complete) + 1):
            with self.subTest(length=length):
                p = parse_packet(0, 1, complete[:length], len(complete))
                self.assertEqual(p.length, len(complete))
                if length < 54:
                    self.assertIn("解析提示", p.details)
                    self.assertIsNone(FlowTracker().add(p))
        malformed = bytearray(tcp())
        malformed[12] = 0x10
        p = parse_packet(0, 101, ipv4(6, malformed))
        self.assertIn("无效", p.info)
        self.assertIsNone(p.dport)
        self.assertIn("未支持", parse_packet(0, 12345, b"").info)

    def test_sll_and_first_fragment(self):
        udp = struct.pack("!HHHH", 111, 222, 240, 0) + bytes(8)
        ip = ipv4(17, udp, fragment=0x2000)
        for link, header in [(113, bytes(14) + b"\x08\x00"),
                             (276, b"\x08\x00" + bytes(18))]:
            p = parse_packet(0, link, header + ip)
            self.assertEqual(p.protocol, "UDP")
            self.assertNotIn("捕获状态", p.details)

    def test_bidirectional_sessions_retransmissions_and_tuple_reuse(self):
        tracker = FlowTracker()

        def add(t, flags, seq=17, reverse=False):
            p = parse_packet(t, 101, ipv4(6, tcp(flags=flags, seq=seq, reverse=reverse), reverse))
            result = tracker.add(p)
            self.assertEqual(result, p.flow_id)
            return result

        self.assertEqual([add(1, 2), add(2, 2), add(3, 18, 30, True), add(4, 16)], [1] * 4)
        self.assertEqual(add(5, 17), 1)
        self.assertEqual(tracker.flows[1].state, "单向已发送 FIN")
        self.assertEqual(add(6, 17, reverse=True), 1)
        self.assertEqual(add(7, 16), 1)
        f = tracker.flows[1]
        self.assertEqual((f.packets_ab, f.packets_ba, f.bytes_ab, f.bytes_ba), (5, 2, 200, 80))
        self.assertEqual((f.endpoint_a, f.endpoint_b), ("127.0.0.1:52001", "127.0.0.2:8088"))
        self.assertEqual((f.first_seen, f.last_seen, f.state), (1, 7, "双方已发送 FIN"))
        self.assertEqual(add(8, 2, seq=222), 2)
        self.assertEqual(add(9, 4, reverse=True), 2)
        self.assertEqual(tracker.flows[2].state, "已复位")
        self.assertEqual(add(10, 2, seq=333), 3)
        self.assertEqual(add(11, 2, seq=444), 4)
        p6 = parse_packet(12, 101, ipv6(6, tcp()))
        self.assertEqual(tracker.add(p6), 5)
        self.assertEqual(tracker.flows[5].endpoint_a, "[::1]:52001")


if __name__ == "__main__":
    unittest.main()
