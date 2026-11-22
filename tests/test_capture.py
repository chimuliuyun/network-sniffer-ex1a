import ctypes as C
import io
import struct
import sys
import unittest
from pathlib import Path
from threading import Event
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import capture


def pcap_bytes(endian="<", magic=0xA1B2C3D4, fraction=250000, original=8):
    header = struct.pack(endian + "IHHIIII", magic, 2, 4, 0, 0, 65535, 1)
    record = struct.pack(endian + "IIII", 12, fraction, 4, original)
    return header + record + b"abcd"


class ClassicPcapTests(unittest.TestCase):
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
