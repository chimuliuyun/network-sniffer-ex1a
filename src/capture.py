"""Passive live capture via Npcap/libpcap and classic pcap stream input."""

import ctypes as C
import ctypes.util
import os
import struct
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from threading import Event
from typing import BinaryIO, Callable


class CaptureError(RuntimeError):
    pass


@dataclass(frozen=True)
class Interface:
    name: str
    description: str


PacketCallback = Callable[[float, int, bytes, int], None]
_SNAPLEN = 262144
_MAX_RECORD = 16 * 1024 * 1024


class _Device(C.Structure):
    pass


_DevicePtr = C.POINTER(_Device)
_Device._fields_ = [
    ("next", _DevicePtr), ("name", C.c_char_p), ("description", C.c_char_p),
    ("addresses", C.c_void_p), ("flags", C.c_uint32),
]


class _Header(C.Structure):
    _fields_ = [
        ("seconds", C.c_long), ("microseconds", C.c_long),
        ("captured", C.c_uint32), ("original", C.c_uint32),
    ]


_HeaderPtr = C.POINTER(_Header)
_DataPtr = C.POINTER(C.c_ubyte)


def _decode(data: bytes | None) -> str:
    if not data:
        return ""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return data.decode("mbcs" if os.name == "nt" else "utf-8", "replace")


@lru_cache(maxsize=1)
def _library():
    if os.name == "nt":
        path = Path(os.environ["SystemRoot"]) / "System32" / "Npcap" / "wpcap.dll"
        if not path.is_file():
            raise CaptureError("未找到 Npcap 驱动库。请安装 Npcap 后刷新网卡列表。")
    else:
        path = ctypes.util.find_library("pcap")
        if not path:
            raise CaptureError("未找到 libpcap 运行库。")
    try:
        lib = C.CDLL(str(path))
    except OSError as exc:
        raise CaptureError(f"无法加载抓包运行库（{exc}）") from exc
    handle = C.c_void_p
    text = C.c_char_p
    signatures = {
        "pcap_findalldevs": (C.c_int, [C.POINTER(_DevicePtr), text]),
        "pcap_freealldevs": (None, [_DevicePtr]),
        "pcap_open_live": (handle, [text, C.c_int, C.c_int, C.c_int, text]),
        "pcap_setnonblock": (C.c_int, [handle, C.c_int, text]),
        "pcap_datalink": (C.c_int, [handle]),
        "pcap_next_ex": (C.c_int, [handle, C.POINTER(_HeaderPtr), C.POINTER(_DataPtr)]),
        "pcap_geterr": (text, [handle]),
        "pcap_close": (None, [handle]),
    }
    for name, (result, args) in signatures.items():
        fn = getattr(lib, name)
        fn.restype = result
        fn.argtypes = args
    return lib


def list_interfaces() -> list[Interface]:
    lib = _library()
    head = _DevicePtr()
    error = C.create_string_buffer(256)
    if lib.pcap_findalldevs(C.byref(head), error) != 0:
        raise CaptureError(f"无法列出网卡（{_decode(error.value)}）")
    interfaces = []
    try:
        current = head
        while current:
            item = current.contents
            name = os.fsdecode(item.name)
            interfaces.append(Interface(name, _decode(item.description) or name))
            current = item.next
    finally:
        if head:
            lib.pcap_freealldevs(head)
    return interfaces


def capture_live(interface_name: str, stop: Event, on_packet: PacketCallback) -> None:
    """Open one interface in non-promiscuous mode. The caller owns the stop event."""
    if stop.is_set():
        return
    lib = _library()
    error = C.create_string_buffer(256)
    handle = lib.pcap_open_live(os.fsencode(interface_name), _SNAPLEN, 0, 50, error)
    if not handle:
        raise CaptureError(f"无法打开网卡（{_decode(error.value)}）")
    try:
        if lib.pcap_setnonblock(handle, 1, error) < 0:
            raise CaptureError(f"无法设置非阻塞捕获（{_decode(error.value)}）")
        datalink = lib.pcap_datalink(handle)
        if datalink < 0:
            raise CaptureError(f"无法读取网卡链路类型（{_decode(lib.pcap_geterr(handle))}）")
        header = _HeaderPtr()
        data = _DataPtr()
        while not stop.is_set():
            status = lib.pcap_next_ex(handle, C.byref(header), C.byref(data))
            if status == 0:
                stop.wait(0.025)
                continue
            if status != 1:
                raise CaptureError(f"读取网卡数据失败（{_decode(lib.pcap_geterr(handle))}）")
            record = header.contents
            # libpcap owns both pointers and may reuse them on the next read.
            payload = C.string_at(data, record.captured)
            on_packet(record.seconds + record.microseconds / 1e6, datalink, payload, record.original)
    finally:
        lib.pcap_close(handle)


_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000), b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000), b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


def _read_exact(stream: BinaryIO, size: int, allow_eof: bool = False) -> bytes:
    data = bytearray()
    while len(data) < size:
        piece = stream.read(size - len(data))
        if not piece:
            if allow_eof and not data:
                return b""
            raise CaptureError("pcap 文件或数据流不完整。")
        data.extend(piece)
    return bytes(data)


def read_pcap(stream: BinaryIO, stop: Event, on_packet: PacketCallback) -> None:
    """Read classic pcap. For live pipes, the owner must close the producer to end a pending read."""
    if stop.is_set():
        return
    header = _read_exact(stream, 24)
    fmt = _MAGIC.get(header[:4])
    if fmt is None:
        raise CaptureError("需要标准 pcap 文件（不支持 pcapng）。")
    endian, divisor = fmt
    major, minor, _, _, snaplen, network = struct.unpack(endian + "HHIIII", header[4:])
    if (major, minor) != (2, 4) or snaplen == 0:
        raise CaptureError("无效或不支持的 pcap 文件头。")
    datalink = network & 0xFFFF
    unpack_record = struct.Struct(endian + "IIII").unpack
    while not stop.is_set():
        record = _read_exact(stream, 16, allow_eof=True)
        if not record:
            return
        sec, fraction, caplen, original = unpack_record(record)
        if fraction >= divisor or caplen > min(snaplen, original, _MAX_RECORD):
            raise CaptureError("无效的 pcap 记录长度或时间戳。")
        on_packet(sec + fraction / divisor, datalink, _read_exact(stream, caplen), original)
