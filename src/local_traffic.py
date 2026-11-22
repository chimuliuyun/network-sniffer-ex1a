"""在回环网卡上产生可识别的 HTTP、UDP 和 ICMP 流量，供抓包验收。"""

from http.client import HTTPConnection
from http.server import BaseHTTPRequestHandler, HTTPServer
import os
import socket
import subprocess
from threading import Thread
from time import sleep


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


def exchange(family, host):
    class LocalServer(HTTPServer):
        address_family = family

    with LocalServer((host, 0), LocalRequest) as server:
        server.timeout = 3
        http_port = server.server_port
        thread = Thread(target=server.handle_request, daemon=True)
        thread.start()
        client = HTTPConnection(host, http_port, timeout=3)
        try:
            client.request("GET", "/experiment-1a")
            response = client.getresponse()
            if response.status != 200 or response.read() != b"experiment-1A\n":
                raise RuntimeError("HTTP 应答与测试内容不符")
            # 让实时嗅探器能在连接仍存在时从 Windows TCP 表读取所属 PID。
            sleep(1.2)
        finally:
            client.close()
            thread.join(timeout=4)

    with socket.socket(family, socket.SOCK_DGRAM) as receiver, socket.socket(family, socket.SOCK_DGRAM) as sender:
        receiver.bind((host, 0))
        receiver.settimeout(3)
        sender.settimeout(3)
        datagram = b"experiment-1A UDP"
        sender.sendto(datagram, receiver.getsockname())
        data, peer = receiver.recvfrom(1024)
        receiver.sendto(data, peer)
        if sender.recv(1024) != datagram:
            raise RuntimeError("UDP 回显与测试内容不符")
        return http_port, receiver.getsockname()[1]


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
