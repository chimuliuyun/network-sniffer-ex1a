"""Passive live capture via Npcap/libpcap and classic pcap stream input."""

import ctypes as C
import ctypes.util
import math
import os
import struct
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from typing import BinaryIO, Callable


class CaptureError(RuntimeError):
    pass


@dataclass(frozen=True)
class Interface:
    name: str
    description: str


@dataclass(frozen=True, slots=True)
class CaptureRecord:
    timestamp: float
    datalink: int
    data: bytes
    original_length: int


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


class _BpfProgram(C.Structure):
    _fields_ = [("length", C.c_uint), ("instructions", C.c_void_p)]


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
        "pcap_compile": (C.c_int, [handle, C.POINTER(_BpfProgram), text, C.c_int, C.c_uint32]),
        "pcap_setfilter": (C.c_int, [handle, C.POINTER(_BpfProgram)]),
        "pcap_freecode": (None, [C.POINTER(_BpfProgram)]),
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


def capture_live(interface_name: str, stop: Event, on_packet: PacketCallback, *,
                 capture_filter: str | None = None, on_ready: Callable[[], None] | None = None) -> None:
    """Open one interface in non-promiscuous mode. The caller owns the stop event."""
    if stop.is_set():
        return
    lib = _library()
    error = C.create_string_buffer(256)
    handle = lib.pcap_open_live(os.fsencode(interface_name), _SNAPLEN, 0, 50, error)
    if not handle:
        raise CaptureError(f"无法打开网卡（{_decode(error.value)}）")
    try:
        if capture_filter:
            program = _BpfProgram()
            if lib.pcap_compile(handle, C.byref(program), capture_filter.encode("ascii"), 1, 0xffffffff) != 0:
                raise CaptureError(f"无法编译抓包条件（{_decode(lib.pcap_geterr(handle))}）")
            try:
                if lib.pcap_setfilter(handle, C.byref(program)) != 0:
                    raise CaptureError(f"无法启用抓包条件（{_decode(lib.pcap_geterr(handle))}）")
            finally:
                lib.pcap_freecode(C.byref(program))
        if lib.pcap_setnonblock(handle, 1, error) < 0:
            raise CaptureError(f"无法设置非阻塞捕获（{_decode(error.value)}）")
        datalink = lib.pcap_datalink(handle)
        if datalink < 0:
            raise CaptureError(f"无法读取网卡链路类型（{_decode(lib.pcap_geterr(handle))}）")
        header = _HeaderPtr()
        data = _DataPtr()
        if on_ready:
            on_ready()
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


def write_pcap(path: Path | str, records: Iterable[CaptureRecord]) -> None:
    """Save a single-link session as classic pcap, replacing the target only on success."""
    records = tuple(records)
    if not records:
        raise CaptureError("没有可导出的数据包。")
    link = records[0].datalink
    if not 0 <= link <= 0xFFFF:
        raise CaptureError("经典 PCAP 无法保存该链路类型。")
    if any(record.datalink != link for record in records):
        raise CaptureError("经典 PCAP 中的所有数据包必须使用同一链路类型。")
    snaplen = max(_SNAPLEN, max(len(record.data) for record in records))
    if snaplen > _MAX_RECORD:
        raise CaptureError("单个捕获记录超过支持的长度。")

    destination = Path(path)
    with TemporaryDirectory(prefix=".pcap-", dir=destination.parent) as temp_dir:
        staging = Path(temp_dir) / "session.pcap"
        with staging.open("wb") as out:
            # Nanosecond-format pcap also represents microsecond captures exactly.
            out.write(struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, snaplen, link))
            for record in records:
                length = len(record.data)
                if not length <= record.original_length <= 0xFFFFFFFF:
                    raise CaptureError("数据包的原始长度无效。")
                timestamp = record.timestamp
                if not math.isfinite(timestamp) or not 0 <= timestamp < 2**32:
                    raise CaptureError("数据包的时间戳超出经典 PCAP 范围。")
                sec = int(timestamp)
                fraction = timestamp - sec
                usec = round(fraction * 1_000_000)
                if sec + usec / 1_000_000 == timestamp:
                    nsec = usec * 1000
                else:
                    nsec = round(fraction * 1_000_000_000)
                carry, nsec = divmod(nsec, 1_000_000_000)
                out.write(struct.pack("<IIII", sec + carry, nsec, length, record.original_length))
                out.write(record.data)
        staging.replace(destination)


def format_hex(data: bytes, limit: int = 1024) -> str:
    """Format captured bytes in 16-byte rows with offsets and printable ASCII."""
    if limit < 0:
        raise ValueError("字节展示上限不能为负数。")
    if not data:
        return "无可展示的捕获字节。"
    shown = min(len(data), limit)
    lines = []
    for start in range(0, shown, 16):
        row = data[start:min(start + 16, shown)]
        hex_column = row.hex(" ").upper()
        ascii_column = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in row)
        lines.append(f"{start:04X}  {hex_column:<47}  |{ascii_column}|")
    if shown < len(data):
        lines.append(f"已显示 {shown:,} / {len(data):,} 字节")
    return "\n".join(lines)
