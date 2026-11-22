"""从 Windows TCP 表读取仍有本机所有者的连接，两端按方向区分。"""

import ctypes
from ipaddress import IPv6Address, ip_address
import os
import socket
import struct


# Windows MIB_TCP[6]ROW_OWNER_PID: DWORD 为小端，地址和端口为网络序。
_ROW4 = struct.Struct("<I4s2s2x4s2s2xI")
_ROW6 = struct.Struct("<16s4x2s2x16s4x2s2xII")
_OWNER_PID_CONNECTIONS = 4
_INSUFFICIENT_BUFFER = 122

OwnerKey = tuple[str, int, str, int]


def _read_table(query, family: int) -> bytes:
    size = ctypes.c_uint32()
    buffer = None
    for _ in range(5):  # New sockets can make the previous size estimate too small.
        status = query(buffer, ctypes.byref(size), False, family, _OWNER_PID_CONNECTIONS, 0)
        if status == 0 and buffer is not None:
            return buffer.raw[:size.value]
        if status == 50 and family == socket.AF_INET6:  # IPv6 not supported
            return bytes(4)
        if status != _INSUFFICIENT_BUFFER:
            raise ctypes.WinError(status)
        buffer = ctypes.create_string_buffer(size.value)
    raise OSError("TCP 表连续增长，未取得一致的快照")


def _read_rows(data: bytes, family: int):
    row = _ROW4 if family == socket.AF_INET else _ROW6
    if len(data) < 4:
        raise OSError("TCP 表缺少行数")
    count = int.from_bytes(data[:4], "little")
    end = 4 + count * row.size
    if end > len(data):
        raise OSError("TCP 表数据不完整")
    for fields in row.iter_unpack(data[4:end]):
        if family == socket.AF_INET:
            state, local, lport, remote, rport, pid = fields
        else:
            local, lport, remote, rport, state, pid = fields
        # Active, connecting and closing sockets carry an owner. Listeners,
        # TIME_WAIT and deleted connections do not identify a live socket owner.
        if not (3 <= state <= 10) or not pid:
            continue
        local, remote = ip_address(local), ip_address(remote)
        if isinstance(local, IPv6Address) and local.ipv4_mapped and remote.ipv4_mapped:
            local, remote = local.ipv4_mapped, remote.ipv4_mapped
        key = (str(local), int.from_bytes(lport, "big"), str(remote), int.from_bytes(rport, "big"))
        yield key, pid


def read_tcp_owners() -> dict[OwnerKey, int]:
    """键为 (本地 IP, 本地端口, 远端 IP, 远端端口)。省略不能唯一归属的端点。"""
    if os.name != "nt":
        raise OSError("本机 TCP 进程关联需要 Windows")
    query = ctypes.windll.iphlpapi.GetExtendedTcpTable
    query.argtypes = (ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32), ctypes.c_int,
                      ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32)
    query.restype = ctypes.c_uint32
    result = {}
    ambiguous = set()
    for family in (socket.AF_INET, socket.AF_INET6):
        for key, pid in _read_rows(_read_table(query, family), family):
            if key in result and result[key] != pid:
                # IPv6 link-local scopes are not available in the packet's IP header.
                ambiguous.add(key)
            result[key] = pid
    for key in ambiguous:
        del result[key]
    return result
