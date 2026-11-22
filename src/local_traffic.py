"""在回环网卡上产生可识别的 HTTP、UDP 和 ICMP 流量，供抓包验收。"""

from contextlib import ExitStack
from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
from pathlib import Path
import secrets
import socket
import subprocess
from threading import Event, Thread
from time import monotonic
from typing import NamedTuple

from capture import CaptureError, PacketCallback, capture_live
from protocols import parse_packet


_HOSTS = ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1"))


class Endpoints(NamedTuple):
    server: HTTPServer
    client: socket.socket
    receiver: socket.socket
    sender: socket.socket

class LocalRequest(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        body = b"experiment-1A\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _open_endpoints(resources, family, host):
    class LocalServer(HTTPServer):
        address_family = family

    server = resources.enter_context(LocalServer((host, 0), LocalRequest))
    server.timeout = 2

    def bound_socket(kind):
        sock = resources.enter_context(socket.socket(family, kind))
        sock.bind((host, 0))
        sock.settimeout(2)
        return sock

    return Endpoints(server, bound_socket(socket.SOCK_STREAM),
                     bound_socket(socket.SOCK_DGRAM), bound_socket(socket.SOCK_DGRAM))


def _exchange(host, endpoints, stop):
    server, outgoing, receiver, sender = endpoints
    outgoing.connect(server.server_address)
    client = HTTPConnection(host, server.server_port, timeout=2)
    client.sock = outgoing
    thread = Thread(target=server.handle_request, daemon=True)
    thread.start()
    try:
        client.request("GET", "/experiment-1a")
        response = client.getresponse()
        if response.status != 200 or response.read() != b"experiment-1A\n":
            raise RuntimeError("HTTP 应答与测试内容不符")
        # 给实时的 Windows TCP 表采样留出时间。
        stop.wait(1.2)
    finally:
        client.close()
        thread.join(timeout=3)

    if not stop.is_set():
        message = b"experiment-1A UDP"
        sender.sendto(message, receiver.getsockname())
        data, peer = receiver.recvfrom(1024)
        if data != message or peer[:2] != sender.getsockname()[:2]:
            raise RuntimeError("UDP 收到的测试报文不符")
        receiver.sendto(data, peer)
        if sender.recv(1024) != message:
            raise RuntimeError("UDP 回显与测试内容不符")
    return server.server_port, receiver.getsockname()[1]


def exchange(family, host):
    with ExitStack() as resources:
        return _exchange(host, _open_endpoints(resources, family, host), Event())


def _marked_pings(marker: bytes, stop: Event):
    """每次实测使用独立的 Echo 载荷，避免把其他程序的 ping 纳入本次结果。"""
    if os.name == "nt":
        executable = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        script = (
            "$ErrorActionPreference='Stop'; $p=New-Object Net.NetworkInformation.Ping; "
            f"$b=[Text.Encoding]::ASCII.GetBytes('{marker.decode('ascii')}'); "
            "try {foreach ($hostIP in '127.0.0.1','::1') {"
            "if ($p.Send([Net.IPAddress]::Parse($hostIP),1000,$b).Status -ne 'Success'){exit 1}"
            "}}finally{$p.Dispose()}"
        )
        commands = [[str(executable), "-NoProfile", "-NonInteractive", "-Command", script]]
    else:
        commands = [["ping", version, "-c", "1", "-s", "64", "-p", marker.hex(), host]
                    for version, host in (("-4", "127.0.0.1"), ("-6", "::1"))]
    for command in commands:
        if stop.is_set():
            return
        with subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)) as ping:
            deadline = monotonic() + 8
            while ping.poll() is None:
                if stop.wait(0.03) or monotonic() > deadline:
                    ping.kill()
                    ping.wait()
                    break
            if ping.returncode and not stop.is_set():
                raise CaptureError("本机 ICMP 回显测试未成功。")


def capture_demo(interface_name: str, stop: Event, on_packet: PacketCallback) -> None:
    """仅采集本轮在回环接口生成的流量，完成后自动关闭抓包句柄。"""
    if stop.is_set():
        return
    if interface_name.rsplit("\\", 1)[-1].casefold() not in ("npf_loopback", "lo", "lo0"):
        raise CaptureError("回环实测需要选择本机回环接口。")
    marker = secrets.token_hex(8).encode("ascii")
    ready, finish, complete = Event(), Event(), Event()
    failure = []
    observed = {host: set() for _, host in _HOSTS}
    with ExitStack() as resources:
        endpoints = {host: _open_endpoints(resources, family, host) for family, host in _HOSTS}
        clauses = []
        for host, channel in endpoints.items():
            tcp = f"(tcp and port {channel.server.server_port} and port {channel.client.getsockname()[1]})"
            udp = f"(udp and port {channel.receiver.getsockname()[1]} and port {channel.sender.getsockname()[1]})"
            if host == "127.0.0.1":
                echo, header, offset = "icmp and (icmp[0] = 0 or icmp[0] = 8)", "icmp", 8
            else:
                echo, header, offset = "icmp6 and (ip6[40] = 128 or ip6[40] = 129)", "ip6", 48
            if os.name == "nt":  # Ping.Send places the marker directly after its ICMP header.
                for pos in range(0, len(marker), 4):
                    echo += f" and {header}[{offset + pos}:4] = 0x{marker[pos:pos + 4].hex()}"
            clauses.append(f"(src host {host} and dst host {host} and ({tcp} or {udp} or ({echo})))")

        def receive(ts, link, data, size):
            packet = parse_packet(ts, link, data, size)
            seen = observed.get(packet.src)
            if seen is None:
                return
            if packet.matches("ICMP"):
                if marker not in data:
                    return
                seen.add(packet.details.get("ICMP 类型"))
            elif packet.matches("HTTP"):
                seen.add(packet.details.get("HTTP 方法") or packet.details.get("HTTP 状态码"))
            elif packet.matches("UDP"):
                receiver_port = endpoints[packet.src].receiver.getsockname()[1]
                seen.add("udp-in" if packet.dport == receiver_port else "udp-out")
            on_packet(ts, link, data, size)
            if ({"GET", "200", "udp-in", "udp-out", "0", "8"} <= observed["127.0.0.1"]
                    and {"GET", "200", "udp-in", "udp-out", "128", "129"} <= observed["::1"]):
                complete.set()

        def read():
            try:
                capture_live(interface_name, finish, receive, capture_filter=" or ".join(clauses), on_ready=ready.set)
            except Exception as exc:
                failure.append(exc)
            finally:
                ready.set()

        reader = Thread(target=read, name="loopback-demo-reader", daemon=True)
        reader.start()
        try:
            while not ready.wait(0.05):
                if stop.is_set():
                    return
            if failure:
                raise failure[0]
            for host, test_sockets in endpoints.items():
                if stop.is_set():
                    return
                _exchange(host, test_sockets, stop)
            _marked_pings(marker, stop)
            deadline = monotonic() + 2
            while not stop.is_set() and not complete.wait(0.05):
                if failure:
                    raise failure[0]
                if monotonic() >= deadline:
                    raise CaptureError("回环实测未捕获完整的双栈 HTTP、UDP 和 ICMP 往返，请重新运行。")
        finally:
            finish.set()
            reader.join()
        if failure and not stop.is_set():
            raise failure[0]


def main():
    print(f"本机测试流量的进程 PID 为 {os.getpid()}", flush=True)
    for family, host in ((socket.AF_INET, "127.0.0.1"), (socket.AF_INET6, "::1")):
        http_port, udp_port = exchange(family, host)
        print(f"{host}  HTTP GET /experiment-1a → 200，TCP 端口 {http_port}；UDP 双向回显，端口 {udp_port}")
        count, size = ("-n", "-l") if os.name == "nt" else ("-c", "-s")
        result = subprocess.run(["ping", "-6" if family == socket.AF_INET6 else "-4",
                                 count, "1", size, "89", host], capture_output=True, timeout=6)
        print(f"{host}  ICMP 回显{'成功' if result.returncode == 0 else '未收到回复'}")
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
