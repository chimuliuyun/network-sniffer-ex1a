"""被动解析抓到的报头，并以 IP 和端口跟踪双向 TCP 会话。"""

from dataclasses import dataclass, field
from ipaddress import ip_address
import re
import struct


@dataclass
class Packet:
    timestamp: float
    length: int
    src: str = ""
    dst: str = ""
    sport: int | None = None
    dport: int | None = None
    layers: tuple[str, ...] = ()
    info: str = ""
    details: dict[str, str] = field(default_factory=dict)
    flow_id: int | None = None
    tcp_flags: int = 0
    tcp_seq: int = 0

    @property
    def protocol(self) -> str:
        return self.layers[-1] if self.layers else "未知"

    def matches(self, name: str) -> bool:
        name = name.strip().lower()
        if name in ("", "all", "全部"):
            return True
        if name == "icmp" and "ICMPv6" in self.layers:
            return True
        return any(layer.lower() == name for layer in self.layers)


class _InvalidHeader(ValueError):
    pass


def _require_header(data: bytes, size: int, label: str) -> None:
    if len(data) < size:
        raise _InvalidHeader(f"{label} 首部截断")


def _network_payload(packet: Packet, link: int, data: bytes) -> tuple[int, bytes]:
    """去除链路层首部，返回 EtherType 和网络层数据。"""
    if link == 1:
        packet.layers = ("Ethernet",)
        _require_header(data, 14, "Ethernet")
        packet.src, packet.dst = data[6:12].hex(":"), data[:6].hex(":")
        packet.details.update({"源 MAC": packet.src, "目的 MAC": packet.dst})
        ether_type = int.from_bytes(data[12:14], "big")
        offset = 14
        tags = []
        while ether_type in (0x8100, 0x88A8, 0x9100):
            _require_header(data, offset + 4, "VLAN")
            tci, ether_type = struct.unpack_from("!HH", data, offset)
            tags.append(str(tci & 0xFFF))
            offset += 4
        if tags:
            packet.layers += ("VLAN",)
            packet.details["VLAN ID（由外到内）"] = " → ".join(tags)
    elif link in (0, 108):   # DLT_NULL uses host byte order, DLT_LOOP network order.
        packet.layers = ("Loopback",)
        _require_header(data, 4, "Loopback")
        families = {2: 0x0800, 10: 0x86DD, 23: 0x86DD, 24: 0x86DD, 28: 0x86DD, 30: 0x86DD}
        family = int.from_bytes(data[:4], "big")
        if link == 0 and family not in families:
            family = int.from_bytes(data[:4], "little")
        packet.details["回环地址族"] = str(family)
        return families.get(family, 0), data[4:]
    elif link in (12, 101, 228, 229):
        _require_header(data, 1, "原始 IP")
        if link == 228:
            return 0x0800, data
        if link == 229:
            return 0x86DD, data
        return {4: 0x0800, 6: 0x86DD}.get(data[0] >> 4, 0), data
    elif link in (113, 276):
        packet.layers = ("Linux cooked",)
        offset = 16 if link == 113 else 20
        _require_header(data, offset, "Linux cooked")
        ether_type = struct.unpack_from("!H", data, 14 if link == 113 else 0)[0]
    else:
        raise _InvalidHeader(f"未支持的链路类型 {link}")
    packet.details["EtherType"] = f"0x{ether_type:04x}"
    return ether_type, data[offset:]


def _ip_payload(packet: Packet, ether_type: int, data: bytes) -> tuple[int, bytes, bool]:
    """返回上层协议、属于本 IP 数据报的有效字节和首分片标志。"""
    ipv4 = ether_type == 0x0800
    layer = "IPv4" if ipv4 else "IPv6"
    packet.layers += (layer,)
    _require_header(data, 20 if ipv4 else 40, layer)
    if data[0] >> 4 != (4 if ipv4 else 6):
        raise _InvalidHeader("首部版本与链路协议不一致")
    if ipv4:
        offset = (data[0] & 15) * 4
        total, ident, fragment = struct.unpack_from("!HHH", data, 2)
        if offset < 20 or total < offset:
            raise _InvalidHeader("IPv4 长度字段无效")
        _require_header(data, offset, layer)
        packet.src, packet.dst = str(ip_address(data[12:16])), str(ip_address(data[16:20]))
        proto = data[9]
        packet.details.update({"IPv4 标识": str(ident), "IPv4 首部长度": str(offset),
                               "TTL": str(data[8]), "IPv4 总长度": str(total), "IP 协议号": str(proto)})
        fragment_offset, more = (fragment & 0x1FFF) * 8, bool(fragment & 0x2000)
    else:
        offset = 40
        payload_length = struct.unpack_from("!H", data, 4)[0]
        proto, total = data[6], 40 + payload_length
        packet.src, packet.dst = str(ip_address(data[8:24])), str(ip_address(data[24:40]))
        packet.details.update({"IPv6 载荷长度": str(payload_length), "跳数限制": str(data[7]),
                               "IPv6 下一首部": str(proto)})
        fragment_offset, more = 0, False
    packet.details.update({"源 IP": packet.src, "目的 IP": packet.dst})
    if len(data) < total:
        packet.details["捕获状态"] = f"IP 数据不全，已捕获 {len(data)} / {total} 字节"
    data = data[:total]   # Ethernet padding is not application payload.
    if not ipv4:
        extensions = []
        while proto in (0, 43, 44, 51, 60):
            _require_header(data, offset + 2, "IPv6 扩展")
            kind = proto
            proto, size = data[offset:offset + 2]
            if kind == 44:
                size = 8
                _require_header(data, offset + size, "IPv6 分片")
                fragment = struct.unpack_from("!H", data, offset + 2)[0]
                fragment_offset, more = fragment & 0xFFF8, bool(fragment & 1)
            elif kind == 51:
                size = (size + 2) * 4
                if size < 12:
                    raise _InvalidHeader("IPv6 AH 长度无效")
            else:
                size = (size + 1) * 8
            _require_header(data, offset + size, "IPv6 扩展")
            offset += size
            extensions.append(str(kind))
            if fragment_offset:
                break
        if extensions:
            packet.details["IPv6 扩展首部类型"] = " → ".join(extensions)
    if more or fragment_offset:
        packet.details["分片偏移（字节）"] = str(fragment_offset)
        packet.details["后续分片"] = "有" if more else "无"
    if fragment_offset:
        packet.info = f"IP 分片，偏移 {fragment_offset} 字节"
        return -1, b"", more
    packet.info = f"上层协议号 {proto}"
    return proto, data[offset:], more


# Match a complete HTTP/1.x start line, regardless of the service port.
_REQUEST = re.compile(rb"([!#$%&'*+.^_`|~0-9A-Za-z-]+) [^\x00-\x20\x7f]+ (HTTP/1\.[01])")
_RESPONSE = re.compile(rb"(HTTP/1\.[01]) ([1-5][0-9]{2}) [^\x00-\x08\x0a-\x1f\x7f]*")
_FLAGS = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
          (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"))


def _parse_transport(packet: Packet, proto: int, data: bytes, more: bool) -> None:
    if proto == 6:
        packet.layers += ("TCP",)
        _require_header(data, 20, "TCP")
        offset = (data[12] >> 4) * 4
        if offset < 20:
            raise _InvalidHeader("TCP 数据偏移无效")
        _require_header(data, offset, "TCP")
        packet.sport, packet.dport, packet.tcp_seq, ack = struct.unpack_from("!HHII", data)
        packet.tcp_flags = data[13]
        flags = ", ".join(name for bit, name in _FLAGS if packet.tcp_flags & bit) or "无"
        window = struct.unpack_from("!H", data, 14)[0]
        payload = data[offset:]
        packet.info = f"{packet.sport} → {packet.dport}  [{flags}]  Seq={packet.tcp_seq}"
        packet.details.update({"TCP 序列号": str(packet.tcp_seq), "TCP 确认号": str(ack), "TCP 标志": flags,
                               "TCP 窗口": str(window), "TCP 首部长度": str(offset),
                               "已捕获 TCP 载荷字节": str(len(payload))})
        end = payload.find(b"\r\n", 0, 8192)
        if end >= 0:
            first_line = payload[:end]
            request = _REQUEST.fullmatch(first_line)
            response = _RESPONSE.fullmatch(first_line)
            if request or response:
                packet.layers += ("HTTP",)
                if request:
                    method, version = (part.decode("ascii") for part in request.groups())
                    packet.info = f"{method}  {version}"
                    packet.details.update({"HTTP 方法": method, "HTTP 版本": version})
                else:
                    version, status = (part.decode("ascii") for part in response.groups())
                    packet.info = f"{version}  {status}"
                    packet.details.update({"HTTP 状态码": status, "HTTP 版本": version})
    elif proto == 17:
        packet.layers += ("UDP",)
        _require_header(data, 8, "UDP")
        src, dst, length = struct.unpack_from("!HHH", data)
        if length < 8:
            raise _InvalidHeader("UDP 长度字段无效")
        packet.sport, packet.dport = src, dst
        packet.info = f"{src} → {dst}  长度 {length}"
        packet.details["UDP 长度"] = str(length)
        if not more and len(data) < length:
            packet.details["捕获状态"] = f"UDP 数据不全，已捕获 {len(data)} / {length} 字节"
    elif (proto == 1 and "IPv4" in packet.layers) or (proto == 58 and "IPv6" in packet.layers):
        layer = "ICMP" if proto == 1 else "ICMPv6"
        packet.layers += (layer,)
        _require_header(data, 4, layer)
        kind, code = data[:2]
        packet.info = f"Type={kind}  Code={code}"
        packet.details.update({"ICMP 类型": str(kind), "ICMP 代码": str(code)})
        echo = (0, 8) if proto == 1 else (129, 128)
        if kind in echo and code == 0:
            _require_header(data, 8, layer)
            ident, seq = struct.unpack_from("!HH", data, 4)
            packet.info = f"Echo {'请求' if kind == echo[1] else '应答'}  Seq={seq}"
            packet.details.update({"Echo 标识": str(ident), "Echo 序号": str(seq)})
    if packet.sport is not None:
        packet.details.update({"源端口": str(packet.sport), "目的端口": str(packet.dport)})


def parse_packet(timestamp: float, datalink: int, data: bytes, wirelen: int | None = None) -> Packet:
    packet = Packet(timestamp, len(data) if wirelen is None else wirelen)
    packet.details.update({"链路类型编号": str(datalink), "原始长度": str(packet.length),
                           "捕获长度": str(len(data))})
    try:
        ether_type, payload = _network_payload(packet, datalink, data)
        if ether_type in (0x0800, 0x86DD):
            proto, transport, more = _ip_payload(packet, ether_type, payload)
            _parse_transport(packet, proto, transport, more)
        else:
            packet.info = f"网络层类型 0x{ether_type:04x}"
    except _InvalidHeader as error:
        packet.info = str(error)
        packet.details["解析提示"] = packet.info
    return packet


Endpoint = tuple[str, int]


def _endpoint_name(endpoint: Endpoint) -> str:
    host, port = endpoint
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


@dataclass
class Flow:
    id: int
    endpoint_a: str
    endpoint_b: str
    first_seen: float
    last_seen: float
    packets_ab: int = 0
    packets_ba: int = 0
    bytes_ab: int = 0
    bytes_ba: int = 0
    state: str = "跟踪中"
    _syn_seq: dict[bool, int] = field(default_factory=dict, repr=False)
    _fin: set[bool] = field(default_factory=set, repr=False)
    _reset: bool = field(default=False, repr=False)


class FlowTracker:
    """A 为首个观测包的发送端。计数含重传，字节数使用原始包长。"""

    def __init__(self):
        self.flows: dict[int, Flow] = {}
        self._latest: dict[tuple[Endpoint, Endpoint], Flow] = {}

    def add(self, packet: Packet) -> int | None:
        if "TCP" not in packet.layers or packet.sport is None or packet.dport is None:
            return None
        src, dst = (packet.src, packet.sport), (packet.dst, packet.dport)
        key = (src, dst) if src <= dst else (dst, src)
        flow = self._latest.get(key)
        sender = _endpoint_name(src)
        flags = packet.tcp_flags
        initial_syn = bool(flags & 2) and not (flags & 16)
        if flow and initial_syn:
            direction = sender == flow.endpoint_a
            seq = flow._syn_seq.get(direction)
            # Identical SYNs are retransmissions; a fresh SYN after closure or a
            # changed initial sequence opens a new connection on the same tuple.
            if flow._reset or flow._fin or (seq is not None and seq != packet.tcp_seq) or (
                seq is None and flow.state == "跟踪中"
            ):
                flow = None
        if flow is None:
            number = len(self.flows) + 1
            flow = Flow(number, sender, _endpoint_name(dst), packet.timestamp, packet.timestamp)
            self.flows[number] = self._latest[key] = flow
        ab = sender == flow.endpoint_a
        packet.flow_id = flow.id
        if ab:
            flow.packets_ab += 1
            flow.bytes_ab += packet.length
        else:
            flow.packets_ba += 1
            flow.bytes_ba += packet.length
        flow.first_seen = min(flow.first_seen, packet.timestamp)
        flow.last_seen = max(flow.last_seen, packet.timestamp)
        if flags & 2:
            flow._syn_seq[ab] = packet.tcp_seq
        if flags & 1:
            flow._fin.add(ab)
        if flags & 4:
            flow._reset = True
        if flow._reset:
            flow.state = "已复位"
        elif len(flow._fin) == 2:
            flow.state = "双方已发送 FIN"
        elif flow._fin:
            flow.state = "单向已发送 FIN"
        elif flags & 2:
            flow.state = "握手中"
        else:
            flow.state = "跟踪中"
        return flow.id
