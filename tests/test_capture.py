import ctypes as C
import io
import os
import struct
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import capture


def pcap_bytes(endian="<", magic=0xA1B2C3D4, fraction=250000, original=8):
    header = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
    record = struct.pack(endian + "IIII", 12, fraction, 4, original)
    return header + record + b"abcd"


class ClassicPcapTests(unittest.TestCase):
    def test_export_sample_and_truncated_record_roundtrip(self):
        def records(path):
            result = []
            with path.open("rb") as stream:
                capture.read_pcap(stream, Event(), lambda *args: result.append(capture.CaptureRecord(*args)))
            return result

        sample = Path(__file__).resolve().parents[1] / "验收样例" / "本机回环.pcap"
        original = records(sample)
        self.assertTrue(original)
        original.append(capture.CaptureRecord(12.000000123, original[0].datalink, b"ab", 42))
        with TemporaryDirectory() as directory:
            path = Path(directory) / "export.pcap"
            capture.write_pcap(path, iter(original))
            self.assertEqual(records(path), original)

    def test_export_failure_preserves_existing_target(self):
        good = capture.CaptureRecord(12.25, 1, b"bytes", 5)
        with TemporaryDirectory() as directory:
            path = Path(directory) / "existing.pcap"
            path.write_bytes(b"old contents")
            for invalid in ([], [good, capture.CaptureRecord(12.3, 0, b"a", 1)],
                            [good, capture.CaptureRecord(12.3, 1, b"abcd", 2)],
                            [good, capture.CaptureRecord(float("nan"), 1, b"a", 1)]):
                with self.subTest(invalid=invalid), self.assertRaises(capture.CaptureError):
                    capture.write_pcap(path, invalid)
                self.assertEqual(path.read_bytes(), b"old contents")
                self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_hex_offsets_ascii_and_display_limit(self):
        data = b"A\x00\xffz" + bytes(range(12)) + b"XY"
        rows = capture.format_hex(data, 17).splitlines()
        self.assertTrue(rows[0].startswith("0000  41 00 FF 7A"))
        self.assertTrue(rows[0].endswith("|A..z............|"))
        self.assertTrue(rows[1].startswith("0010  58 "))
        self.assertTrue(rows[1].endswith("|X|"))
        self.assertIn("17 / 18", rows[2])
        self.assertEqual(len(capture.format_hex(data, 18).splitlines()), 2)

    def test_both_byte_orders_and_timestamp_resolutions(self):
        for endian in ("<", ">"):
            for magic, frac in ((0xA1B2C3D4, 250000), (0xA1B23C4D, 250000000)):
                with self.subTest(endian=endian, magic=magic):
                    callback = Mock()
                    source = io.BytesIO(pcap_bytes(endian, magic, frac))
                    capture.read_pcap(source, Event(), callback)
                    callback.assert_called_once_with(12.25, 1, b"abcd", 8)

    def test_reads_fragmented_stream(self):
        class SlowStream(io.BytesIO):
            def read(self, count):
                return super().read(min(count, 2))

        callback = Mock()
        capture.read_pcap(SlowStream(pcap_bytes()), Event(), callback)
        callback.assert_called_once_with(12.25, 1, b"abcd", 8)

    def test_rejects_truncation_bad_lengths_and_unknown_format(self):
        valid = pcap_bytes()
        for malformed in (valid[:12], valid[:-1], valid[:27], pcap_bytes(original=2),
                          pcap_bytes(fraction=1_000_000), b"\x0a\x0d\x0d\x0a" + valid[4:]):
            with self.subTest(size=len(malformed)), self.assertRaises(capture.CaptureError):
                capture.read_pcap(io.BytesIO(malformed), Event(), Mock())


class LiveApiTests(unittest.TestCase):
    @unittest.skipUnless(os.name == "nt", "Windows Npcap DLL layout")
    def test_missing_npcap_can_be_retried_in_the_system_directory(self):
        capture._library.cache_clear()
        self.addCleanup(capture._library.cache_clear)
        with TemporaryDirectory() as folder, patch.dict(os.environ, {"SystemRoot": folder}):
            with self.assertRaisesRegex(capture.CaptureError, "安装 Npcap"):
                capture.list_interfaces()
            dll = Path(folder) / "System32" / "Npcap" / "wpcap.dll"
            dll.parent.mkdir(parents=True)
            dll.touch()
            with patch.object(C, "CDLL") as load:
                load.side_effect = C.WinError(193)
                with self.assertRaisesRegex(capture.CaptureError, "架构"):
                    capture.list_interfaces()
                load.assert_called_once_with(str(dll))
                load.side_effect = None
                self.assertIs(capture._library(), load.return_value)

    @unittest.skipUnless(os.name == "nt", "Windows driver diagnostics")
    @patch("capture._library")
    def test_driver_error_and_access_denied_preserve_npcap_messages(self, library):
        def fail_list(head, error):
            error.value = b"driver unavailable"
            return -1

        def fail_open(device, size, promisc, timeout, error):
            error.value = b"Access is denied. (5)"
            return None

        api = library.return_value
        api.pcap_findalldevs.side_effect = fail_list
        with self.assertRaisesRegex(capture.CaptureError, "driver unavailable.*sc.exe query npcap"):
            capture.list_interfaces()
        api.pcap_open_live.side_effect = fail_open
        with self.assertRaisesRegex(capture.CaptureError, "Access is denied.*管理员"):
            capture.capture_live("adapter", Event(), Mock())
        api.pcap_close.assert_not_called()

    @patch("capture._library")
    def test_passive_mode_callback_and_close(self, library):
        api = library.return_value
        api.pcap_open_live.return_value = 23
        api.pcap_setnonblock.return_value = 0
        api.pcap_datalink.return_value = 0
        header = capture._Header(76, 500000, 4, 9)
        payload = (C.c_ubyte * 4)(17, 18, 19, 20)

        def next_packet(handle, header_ptr, data_ptr):
            C.cast(header_ptr, C.POINTER(capture._HeaderPtr))[0] = C.pointer(header)
            C.cast(data_ptr, C.POINTER(capture._DataPtr))[0] = C.cast(payload, capture._DataPtr)
            return 1

        api.pcap_next_ex.side_effect = next_packet
        stop = Event()
        callback = Mock(side_effect=lambda *args: stop.set())
        capture.capture_live("loopback", stop, callback)
        self.assertEqual(api.pcap_open_live.call_args.args[2], 0)
        callback.assert_called_once_with(76.5, 0, bytes(payload), 9)
        api.pcap_close.assert_called_once_with(23)

    @patch("capture._library")
    def test_handle_closed_when_read_fails(self, library):
        api = library.return_value
        api.pcap_open_live.return_value = 23
        api.pcap_setnonblock.return_value = 0
        api.pcap_datalink.return_value = 1
        api.pcap_next_ex.return_value = -1
        api.pcap_geterr.return_value = b"device disconnected"
        with self.assertRaisesRegex(capture.CaptureError, "device disconnected"):
            capture.capture_live("adapter", Event(), Mock())
        api.pcap_close.assert_called_once_with(23)


if __name__ == "__main__":
    unittest.main()
