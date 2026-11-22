"""实验 1A 的本地图形界面。工作线程读包，Tk 主线程维护可见状态。"""

from __future__ import annotations

import os
import queue
import threading
import time
import tkinter as tk
from collections import deque
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, ttk

from capture import CaptureError, capture_live, list_interfaces, read_pcap
from owners import read_tcp_owners
from protocols import FlowTracker, Packet, parse_packet


PACKET_LIMIT = 5000
FILTERS = ("全部", "HTTP", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ICMPv6")


def _is_loopback(name: str) -> bool:
    return name.rsplit("\\", 1)[-1].casefold() in ("npf_loopback", "lo", "lo0")


def _time(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]


def _endpoint(address: str, port: int | None) -> str:
    if port is None:
        return address
    if ":" in address:
        return f"[{address}]:{port}"
    return f"{address}:{port}"


def _table(parent, columns):
    frame = ttk.Frame(parent)
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    tree = ttk.Treeview(frame, columns=[c[0] for c in columns],
                        show="headings", selectmode="browse")
    for key, title, width, stretch in columns:
        tree.heading(key, text=title, anchor="w")
        tree.column(key, width=width, minwidth=40, stretch=stretch)
    vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
    tree.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")
    return frame, tree


class SnifferApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.sources: dict[str, str] = {}
        self.packets: list[Packet] = []
        self.tracker = FlowTracker()
        self.running = False
        self.worker: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.closing = threading.Event()
        self.events = queue.Queue(maxsize=256)
        self.selected_flow: int | None = None
        self.displayed = 0
        self.source_name = tk.StringVar(root)
        self.filter_var = tk.StringVar(root, "全部")
        self.status_var = tk.StringVar(root)
        self.count_var = tk.StringVar(root)
        self.flow_var = tk.StringVar(root)
        self.pid_var = tk.StringVar(root)
        self.process_note = tk.StringVar(root)
        self._build()
        self._reset_session()
        self.refresh_interfaces()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.timer = self.root.after(40, self._poll)

    def _build(self):
        root = self.root
        root.title("网络嗅探器 · 实验 1A")
        root.geometry("1100x740")
        root.minsize(760, 550)
        body = ttk.Frame(root, padding=(14, 12))
        body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(2, weight=1)

        bar = ttk.Frame(body)
        bar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        bar.columnconfigure(1, weight=1)
        ttk.Label(bar, text="抓包接口").grid(row=0, column=0, padx=(0, 7))
        self.source_box = ttk.Combobox(bar, textvariable=self.source_name, state="readonly")
        self.source_box.grid(row=0, column=1, sticky="ew")
        self.refresh_button = ttk.Button(bar, text="刷新接口", command=self.refresh_interfaces)
        self.refresh_button.grid(row=0, column=2, padx=(6, 12))
        self.start_button = ttk.Button(bar, text="开始抓包", command=self.start_capture)
        self.start_button.grid(row=0, column=3)
        self.stop_button = ttk.Button(bar, text="停止", command=self.stop_capture)
        self.stop_button.grid(row=0, column=4, padx=6)
        self.open_button = ttk.Button(bar, text="打开 PCAP…", command=self.open_capture)
        self.open_button.grid(row=0, column=5)

        filters = ttk.Frame(body)
        filters.grid(row=1, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(filters, text="协议筛选").pack(side="left", padx=(0, 7))
        self.filter_box = ttk.Combobox(filters, textvariable=self.filter_var, values=FILTERS,
                                       width=12, state="readonly")
        self.filter_box.pack(side="left")
        self.filter_box.bind("<<ComboboxSelected>>", self.apply_filter)
        ttk.Label(filters, textvariable=self.count_var).pack(side="right")

        split = ttk.Panedwindow(body, orient="vertical")
        split.grid(row=2, column=0, sticky="nsew")
        listing, self.packet_tree = _table(split, [
            ("number", "序号", 55, False), ("time", "时间", 110, False),
            ("src", "源地址", 155, True), ("dst", "目的地址", 155, True),
            ("protocol", "协议", 72, False), ("length", "线长 / B", 76, False),
            ("info", "摘要", 310, True),
        ])
        split.add(listing, weight=3)
        self.packet_tree.bind("<<TreeviewSelect>>", self._selected)
        self.notebook = ttk.Notebook(split)
        split.add(self.notebook, weight=2)
        fields, self.field_tree = _table(self.notebook, [
            ("name", "字段", 210, False), ("value", "解析结果", 680, True),
        ])
        self.notebook.add(fields, text="字段解析")
        flow = ttk.Frame(self.notebook, padding=(5, 3))
        self.notebook.add(flow, text="TCP 流追踪")
        summary = ttk.Label(flow, textvariable=self.flow_var, justify="left", wraplength=700)
        summary.pack(fill="x", pady=(1, 4))
        timeline, self.flow_tree = _table(flow, [
            ("number", "包序号", 60, False), ("time", "时间", 110, False),
            ("src", "源端点", 175, True), ("dst", "目的端点", 175, True),
            ("length", "线长 / B", 76, False), ("info", "摘要", 270, True),
        ])
        timeline.pack(fill="both", expand=True)
        processes = ttk.Frame(self.notebook, padding=(5, 3))
        self.notebook.add(processes, text="进程 TCP 流")
        controls = ttk.Frame(processes)
        controls.pack(fill="x", pady=(1, 4))
        ttk.Label(controls, text="本机 PID").pack(side="left", padx=(0, 5))
        self.pid_box = ttk.Combobox(controls, textvariable=self.pid_var, width=8, state="readonly")
        self.pid_box.pack(side="left")
        self.pid_box.bind("<<ComboboxSelected>>", self._refresh_processes)
        ttk.Button(controls, text="查看包时间线", command=self._open_process_flow).pack(side="right")
        process_note = ttk.Label(processes, textvariable=self.process_note, anchor="w", wraplength=700)
        process_note.pack(fill="x", pady=(0, 3))
        process_table, self.process_tree = _table(processes, [
            ("id", "流", 48, False), ("a", "端点 A", 185, True), ("a_pid", "PID A", 74, False),
            ("b", "端点 B", 185, True), ("b_pid", "PID B", 74, False),
            ("ab", "A→B 包", 70, False), ("ba", "B→A 包", 70, False), ("state", "状态", 95, True),
        ])
        process_table.pack(fill="both", expand=True)
        self.process_tree.bind("<Double-1>", self._open_process_flow)
        status = ttk.Label(body, textvariable=self.status_var, anchor="w", wraplength=700)
        status.grid(row=3, column=0, sticky="ew", pady=(7, 0))
        for label in (summary, process_note, status):
            label.bind("<Configure>", lambda event: event.widget.configure(wraplength=max(1, event.width - 4)))

    def _buttons(self):
        self.source_box.configure(state="disabled" if self.running else "readonly")
        self.refresh_button.configure(state="disabled" if self.running else "normal")
        self.start_button.configure(state="normal" if self.sources and not self.running else "disabled")
        self.stop_button.configure(state="normal" if self.running else "disabled")
        self.open_button.configure(state="disabled" if self.running else "normal")

    def refresh_interfaces(self):
        if self.running:
            return
        previous_name = self.sources.get(self.source_name.get())
        self.sources.clear()
        notice = ""
        try:
            for interface in sorted(list_interfaces(), key=lambda dev: not _is_loopback(dev.name)):
                name = interface.name
                label = interface.description or name
                if _is_loopback(name):
                    label = f"本机回环 · {label}"
                if label in self.sources:
                    label = f"{label} ({name})"
                self.sources[label] = name
        except (CaptureError, OSError) as exc:
            notice = str(exc)
        self.source_box.configure(values=tuple(self.sources))
        selected = next((label for label, name in self.sources.items() if name == previous_name),
                        next(iter(self.sources), ""))
        self.source_name.set(selected)
        if notice:
            self.status_var.set(f"网卡枚举提示：{notice}")
        elif self.sources:
            self.status_var.set("就绪。选择接口开始抓包，或打开已有的 PCAP 文件。")
        else:
            self.status_var.set("未找到抓包接口。可刷新接口或打开已有的 PCAP 文件。")
        self._buttons()

    def _reset_session(self):
        self.packets.clear()
        self.tracker = FlowTracker()
        self.selected_flow = None
        self.displayed = 0
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.field_tree.delete(*self.field_tree.get_children())
        self.flow_tree.delete(*self.flow_tree.get_children())
        self.flow_var.set("选择一个 TCP 或 HTTP 数据包，查看该连接两个方向的记录。")
        self.owner_samples = deque(maxlen=8)
        self.collect_owners = False
        self.flow_keys = {}
        self.flow_owners: dict[int, dict[str, int | None]] = {}
        self.process_rows = {}
        self.process_tree.delete(*self.process_tree.get_children())
        self.pid_box.configure(values=())
        self.pid_var.set("")
        self.process_note.set("从 Windows 网卡实时抓包时，可按本机 PID 查看已匹配的连接。")
        self.next_process_refresh = 0.0
        self._counts()

    def _counts(self):
        self.count_var.set(f"已记录 {len(self.packets):,} 包　显示 {self.displayed:,} 包　"
                           f"TCP 流 {len(self.tracker.flows):,} 条")

    def start_capture(self):
        label = self.source_name.get()
        if self.running or label not in self.sources:
            return
        name = self.sources[label]
        local_npcap = os.name == "nt" and name.casefold().startswith("\\device\\npf_")
        self._run(lambda stop, callback: capture_live(name, stop, callback),
                  f"正在抓包　{label}", "抓包已结束", owner_tables=local_npcap)

    def open_capture(self, path=None):
        if self.running:
            return
        if path is None:
            path = filedialog.askopenfilename(
                parent=self.root, title="打开经典 PCAP 文件",
                filetypes=[("经典 PCAP", "*.pcap *.cap"), ("所有文件", "*.*")])
        if not path:
            return
        path = Path(path)

        def reader(stop, callback):
            with path.open("rb") as stream:
                read_pcap(stream, stop, callback)

        self._run(reader, f"正在读取　{path.name}", f"读取完成　{path.name}")
        self.process_note.set("经典 PCAP 没有进程 PID 元数据。此页仅适用于 Windows 本机实时抓包。")

    def _run(self, source, active_text, done_text, *, owner_tables=False):
        self._reset_session()
        self.stop_event = threading.Event()
        self.running = True
        self._buttons()
        self.status_var.set(active_text)
        self.collect_owners = owner_tables
        if owner_tables:
            self.process_note.set("按 PID 查看已匹配的流。系统快照未观测到的端点显示为“—”。")
        stop = self.stop_event

        def put(event, *, final=False):
            while not self.closing.is_set() and (final or not stop.is_set()):
                try:
                    self.events.put(event, timeout=0.1)
                    return True
                except queue.Full:
                    continue
            return False

        def sample_owners():
            while not stop.is_set():
                begin = time.time()
                try:
                    table = read_tcp_owners()
                except OSError as exc:
                    put(("owner_error", f"读取系统 TCP 表失败：{exc}"))
                    return
                put(("owners", (begin, time.time(), table)))
                stop.wait(0.30)

        def worker():
            count = 0

            def received(timestamp, datalink, data, wirelen):
                nonlocal count
                if stop.is_set():
                    return
                packet = parse_packet(timestamp, datalink, data, wirelen)
                if put(("packet", packet)):
                    count += 1
                    if count >= PACKET_LIMIT:
                        stop.set()

            sampler = None
            if owner_tables:
                sampler = threading.Thread(target=sample_owners, daemon=True, name="tcp-owners")
                sampler.start()
            try:
                source(stop, received)
                if count >= PACKET_LIMIT:
                    message = f"已达到单次记录上限 {PACKET_LIMIT:,} 包，采集已停止。"
                elif stop.is_set():
                    message = "已停止。"
                else:
                    message = done_text
            except Exception as exc:
                message = f"采集失败：{exc}"
            finally:
                stop.set()
                if sampler is not None:
                    sampler.join()
            put(("end", message), final=True)

        self.worker = threading.Thread(target=worker, daemon=True, name="packet-capture")
        self.worker.start()

    def stop_capture(self):
        if self.running:
            self.stop_event.set()
            self.stop_button.configure(state="disabled")
            self.status_var.set("正在停止，等待抓包接口关闭…")

    def _poll(self):
        changed = False
        for _ in range(150):
            try:
                kind, value = self.events.get_nowait()
            except queue.Empty:
                break
            if kind == "end":
                self.running = False
                self._buttons()
                self.status_var.set(value)
                self._refresh_processes()
                break
            if kind == "owners":
                self.owner_samples.append(value)
                for flow_id, key in self.flow_keys.items():
                    self._match_owners(flow_id, key, (value,))
                continue
            if kind == "owner_error":
                self.process_note.set(value)
                continue
            self._append(value)
            changed = True
        if changed:
            self._counts()
            if self.selected_flow is not None:
                self._flow_summary()
        if self.running and self.flow_owners and time.monotonic() >= self.next_process_refresh:
            self._refresh_processes()
            self.next_process_refresh = time.monotonic() + 0.35
        self.timer = self.root.after(35, self._poll)

    def _append(self, packet):
        self.tracker.add(packet)
        if packet.flow_id is not None and self.collect_owners:
            # FlowTracker defines A as the first observed sender, even midstream.
            key = self.flow_keys.setdefault(packet.flow_id, (packet.src, packet.sport, packet.dst, packet.dport))
            self._match_owners(packet.flow_id, key, self.owner_samples)
        self.packets.append(packet)
        number = len(self.packets)
        if packet.matches(self.filter_var.get()):
            self._insert_packet(number, packet)
        if packet.flow_id is not None and packet.flow_id == self.selected_flow:
            self._insert_flow(number, packet)

    def _insert_packet(self, number, packet):
        self.packet_tree.insert("", "end", iid=str(number), values=(
            number, _time(packet.timestamp), packet.src, packet.dst,
            packet.protocol, packet.length, packet.info))
        self.displayed += 1

    def apply_filter(self, event=None):
        previous = self.packet_tree.selection()
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.displayed = 0
        selected_filter = self.filter_var.get()
        for number, packet in enumerate(self.packets, 1):
            if packet.matches(selected_filter):
                self._insert_packet(number, packet)
        if previous and self.packet_tree.exists(previous[0]):
            self.packet_tree.selection_set(previous[0])
            self.packet_tree.see(previous[0])
        self._selected()
        self._counts()

    def _selected(self, event=None):
        selection = self.packet_tree.selection()
        self.field_tree.delete(*self.field_tree.get_children())
        packet = self.packets[int(selection[0]) - 1] if selection else None
        if packet is not None:
            for field, value in packet.details.items():
                self.field_tree.insert("", "end", values=(field, value))
        flow_id = packet.flow_id if packet else None
        if flow_id != self.selected_flow:
            self.selected_flow = flow_id
            self.flow_tree.delete(*self.flow_tree.get_children())
            if flow_id is not None:
                for number, other in enumerate(self.packets, 1):
                    if other.flow_id == flow_id:
                        self._insert_flow(number, other)
        self._flow_summary()

    def _flow_summary(self):
        if self.selected_flow is None:
            self.flow_var.set("选择一个 TCP 或 HTTP 数据包，查看该连接两个方向的记录。")
            return
        flow = self.tracker.flows[self.selected_flow]
        self.flow_var.set(
            f"流 #{flow.id}　 A {flow.endpoint_a}　 B {flow.endpoint_b}　 {flow.state}\n"
            f"A → B　{flow.packets_ab} 包 / {flow.bytes_ab:,} B　　 "
            f"B → A　{flow.packets_ba} 包 / {flow.bytes_ba:,} B")

    def _insert_flow(self, number, packet):
        self.flow_tree.insert("", "end", iid=str(number), values=(
            number, _time(packet.timestamp), _endpoint(packet.src, packet.sport),
            _endpoint(packet.dst, packet.dport), packet.length, packet.info))

    def _match_owners(self, flow_id, key, samples):
        flow = self.tracker.flows[flow_id]
        for begin, end, table in samples:
            # Require captured traffic on both sides of the complete table read.
            # A snapshot belonging to an earlier use of the same tuple cannot qualify.
            if not flow.first_seen <= begin <= end <= flow.last_seen:
                continue
            for side, direction in (("A", key), ("B", key[2:] + key[:2])):
                pid = table.get(direction)
                if pid is None:
                    continue
                owners = self.flow_owners.setdefault(flow_id, {})
                if owners.setdefault(side, pid) != pid:
                    owners[side] = None  # Two owners for one endpoint: keep it unknown.

    def _refresh_processes(self, event=None):
        pids = sorted({pid for owners in self.flow_owners.values() for pid in owners.values() if pid})
        self.pid_box.configure(values=pids)
        chosen = self.pid_var.get()
        pid = int(chosen) if chosen else None
        if pid not in pids:
            pid = pids[0] if pids else None
            self.pid_var.set(str(pid) if pid is not None else "")
        rows = {}
        for flow_id, owners in self.flow_owners.items():
            if pid is None or pid not in owners.values():
                continue
            flow = self.tracker.flows[flow_id]
            row = (flow.id, flow.endpoint_a, owners.get("A") or "—",
                   flow.endpoint_b, owners.get("B") or "—",
                   flow.packets_ab, flow.packets_ba, flow.state)
            rows[flow_id] = row
            if flow_id not in self.process_rows:
                self.process_tree.insert("", "end", iid=str(flow_id), values=row)
            elif row != self.process_rows[flow_id]:
                self.process_tree.item(str(flow_id), values=row)
        for removed in self.process_rows.keys() - rows.keys():
            self.process_tree.delete(str(removed))
        self.process_rows = rows

    def _open_process_flow(self, event=None):
        selection = self.process_tree.selection()
        if not selection:
            return
        flow_id = int(selection[0])
        numbers = [str(i) for i, pkt in enumerate(self.packets, 1) if pkt.flow_id == flow_id]
        number = next((n for n in numbers if self.packet_tree.exists(n)), None)
        if number is None:
            self.filter_var.set("TCP")
            self.apply_filter()
            number = numbers[0]
        self.packet_tree.selection_set(number)
        self.packet_tree.see(number)
        self._selected()
        self.notebook.select(1)

    def close(self):
        if self.closing.is_set():
            return
        self.closing.set()
        self.stop_event.set()
        self.root.after_cancel(self.timer)
        self.root.withdraw()
        self._finish_close()

    def _finish_close(self):
        if self.worker is not None and self.worker.is_alive():
            self.root.after(30, self._finish_close)
        else:
            self.root.destroy()


if __name__ == "__main__":
    window = tk.Tk()
    SnifferApp(window)
    window.mainloop()
