"""以本机回环连接核对 Windows TCP 表中两个方向的进程归属。"""

import ctypes
from ipaddress import ip_address
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import owners


def row4(state, pid):
    return owners._ROW4.pack(state, ip_address("127.0.0.1").packed, (50001).to_bytes(2, "big"),
                             ip_address("127.0.0.2").packed, (8080).to_bytes(2, "big"), pid)


class OwnerTests(unittest.TestCase):
    def test_skips_listener_pid_zero_and_time_wait(self):
        entries = [(2, 71), (3, 72), (5, 0), (8, 73), (11, 0), (11, 74), (12, 75)]
        data = struct.pack("<I", len(entries)) + b"".join(row4(*entry) for entry in entries)
        rows = list(owners._read_rows(data, socket.AF_INET))
        key = ("127.0.0.1", 50001, "127.0.0.2", 8080)
        self.assertEqual(rows, [(key, 72), (key, 73)])

    def test_table_resizes_while_querying(self):
        calls = []

        def growing_table(buffer, pointer, ordered, family, table_class, reserved):
            size = ctypes.cast(pointer, ctypes.POINTER(ctypes.c_uint32))
            calls.append(size[0])
            if len(calls) <= 2:
                size[0] = 16 * len(calls)
                return 122
            ctypes.memmove(buffer, bytes(4), 4)
            size[0] = 4
            return 0

        self.assertEqual(owners._read_table(growing_table, socket.AF_INET), bytes(4))
        self.assertEqual(calls, [0, 16, 32])

    @unittest.skipUnless(os.name == "nt", "Windows TCP API")
    def test_ambiguous_owner_not_reported(self):
        rows = struct.pack("<I", 2) + row4(5, 16) + row4(5, 17)
        with mock.patch.object(owners, "_read_table", side_effect=[rows, bytes(4)]):
            self.assertEqual(owners.read_tcp_owners(), {})

    @unittest.skipUnless(os.name == "nt", "Windows TCP API")
    def test_live_ipv4_and_ipv6_owner_per_direction(self):
        # A separate client process proves that reversing a tuple swaps owners.
        child_code = ("import socket,sys\n"
                      "with socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=10) as s:\n"
                      "    s.recv(1)\n")
        for family, host in [(socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")]:
            with self.subTest(host=host), socket.socket(family, socket.SOCK_STREAM) as server:
                server.bind((host, 0))
                server.listen(1)
                server.settimeout(8)
                server_port = server.getsockname()[1]
                with subprocess.Popen([sys.executable, "-c", child_code, host, str(server_port)]) as child:
                    conn, peer = server.accept()
                    with conn:
                        table = owners.read_tcp_owners()
                        client_port = peer[1]
                        self.assertEqual(table[(host, server_port, host, client_port)], os.getpid())
                        self.assertEqual(table[(host, client_port, host, server_port)], child.pid)
                        conn.sendall(b".")
                    self.assertEqual(child.wait(timeout=3), 0)


if __name__ == "__main__":
    unittest.main()
