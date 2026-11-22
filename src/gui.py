"""实验 1A 的本地图形界面。工作线程读包，Tk 主线程维护可见状态。"""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
import tkinter as tk
from collections import deque
from datetime import datetime
from pathlib import Path
from tkinter import filedialog

from capture import CaptureError, CaptureRecord, capture_live, format_hex, list_interfaces, read_pcap, write_pcap
from local_traffic import capture_demo
from owners import read_tcp_owners
from protocols import FlowTracker, Packet, parse_packet
from ui_layout import build_window


PACKET_LIMIT = 5000
BYTE_LIMIT = 64 * 1024 * 1024
SAMPLE_PATH = Path(__file__).resolve().parents[1] / "验收样例" / "本机回环.pcap"


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


def _format_size(size: int) -> str:
    if size < 1024:
        return f"{size:,} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KiB"
    return f"{size / (1024 * 1024):.1f} MiB"


class SnifferApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.sources: dict[str, str] = {}
        self.packets: list[Packet] = []
        self.records: list[CaptureRecord] = []
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
        self.flow_var = tk.StringVar(root)
        self.pid_var = tk.StringVar(root)
        self.process_note = tk.StringVar(root)
        self.query_var = tk.StringVar(root)
        self.mode_var = tk.StringVar(root, "就绪")
        self.session_var = tk.StringVar(root, "等待开始采集")
        self.count_var = tk.StringVar(root)
        self.selected_var = tk.StringVar(root)
        self.flow_choice_var = tk.StringVar(root)
        self.filter_timer = None
        build_window(self)
        self.flow_tree.bind("<Double-1>", self.inspect_flow_packet)
        self.flow_tree.bind("<Return>", self.inspect_flow_packet)
        self.query_var.trace_add("write", self.schedule_filter)
        self._reset_session()
        self.refresh_interfaces()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.timer = self.root.after(40, self._poll)

    def _buttons(self):
        self.source_box.configure(state="disabled" if self.running else "readonly")
        self.refresh_button.configure(state="disabled" if self.running else "normal")
        self.start_button.configure(state="normal" if self.sources and not self.running else "disabled")
        self.stop_button.configure(state="normal" if self.running else "disabled")
        self.open_button.configure(state="disabled" if self.running else "normal")
        self.sample_button.configure(state="disabled" if self.running else "normal")
        self.export_button.configure(state="normal" if self.records and not self.running else "disabled")
        demo_ready = any(_is_loopback(name) for name in self.sources.values())
        self.demo_button.configure(state="normal" if demo_ready and not self.running else "disabled")

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
        self.records.clear()
        self.wire_bytes = 0
        self.flow_labels = {}
        self.flow_options_count = 0
        self.flow_choice_var.set("")
        self.flow_box.configure(values=())
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
        self._selected()
        self._counts()

    def _counts(self):
        self.count_var.set(f"已记录 {len(self.packets):,} 包　显示 {self.displayed:,} 包　"
                           f"TCP 流 {len(self.tracker.flows):,} 条　总线长 {_format_size(self.wire_bytes)}")
        if self.displayed:
            self.empty_panel.place_forget()
        else:
            if self.packets:
                hint = "没有匹配的数据包。可清空搜索或切换协议。"
            elif self.running:
                hint = "正在等待数据包…"
            else:
                hint = "点击「开始抓包」，或打开实验样例。"
            self.empty_var.set(hint)
            self.empty_panel.place(relx=.5, rely=.48, anchor="center")

    def start_capture(self):
        label = self.source_name.get()
        if self.running or label not in self.sources:
            return
        name = self.sources[label]
        local_npcap = os.name == "nt" and name.casefold().startswith("\\device\\npf_")
        self._run(lambda stop, callback: capture_live(name, stop, callback),
                  mode="实时抓包", source_name=label, owner_tables=local_npcap)

    def start_demo(self):
        if self.running:
            return
        label = next((k for k, name in self.sources.items() if _is_loopback(name)), None)
        if label is None:
            self.status_var.set("没有找到本机回环接口，请检查 Npcap 后刷新。")
            return
        self.source_name.set(label)
        self.filter_var.set("全部")
        self.query_var.set("")
        name = self.sources[label]
        self._run(lambda stop, callback: capture_demo(name, stop, callback),
                  mode="回环实测", source_name=f"本机回环 · PID {os.getpid()}", owner_tables=os.name == "nt")

    def open_sample(self):
        self.open_capture(SAMPLE_PATH, sample=True)

    def open_capture(self, path=None, *, sample=False):
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

        self._run(reader, mode="实验样例" if sample else "离线文件", source_name=path.name, offline=True)

    def export_capture(self, path=None):
        if self.running or not self.records:
            return
        if path is None:
            path = filedialog.asksaveasfilename(
                parent=self.root, title="导出完整会话", defaultextension=".pcap",
                initialfile=f"网络抓包_{datetime.now():%Y%m%d_%H%M%S}.pcap",
                filetypes=[("经典 PCAP", "*.pcap")])
        if not path:
            return
        try:
            write_pcap(path, self.records)
        except (CaptureError, OSError) as exc:
            self.status_var.set(f"导出失败 · {exc}")
        else:
            self.status_var.set(f"已导出 {len(self.records):,} 包 · {path}")

    def _run(self, source, *, mode, source_name, owner_tables=False, offline=False):
        if not offline:
            self._reset_session()
            self.mode_var.set(mode)
            self.session_var.set(source_name)
        self.stop_event = threading.Event()
        self.running = True
        self._buttons()
        self.status_var.set(f"正在读取 {source_name}…" if offline else f"{mode}进行中…")
        if not offline:
            self.collect_owners = owner_tables
        self._counts()
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
            raw_bytes = 0
            limit_message = ""
            pending = []

            def received(timestamp, datalink, data, wirelen):
                nonlocal count, raw_bytes, limit_message
                if stop.is_set():
                    return
                if raw_bytes + len(data) > BYTE_LIMIT:
                    limit_message = "原始包已达单次内存上限 64 MiB，采集已停止。"
                    stop.set()
                    return
                record = CaptureRecord(timestamp, datalink, data, wirelen)
                packet = parse_packet(timestamp, datalink, data, wirelen)
                if offline:
                    pending.append((packet, record))
                elif not put(("packet", (packet, record))):
                    return
                count += 1
                raw_bytes += len(data)
                if count >= PACKET_LIMIT:
                    limit_message = f"已达到单次记录上限 {PACKET_LIMIT:,} 包，采集已停止。"
                    stop.set()

            sampler = None
            if owner_tables:
                sampler = threading.Thread(target=sample_owners, daemon=True, name="tcp-owners")
                sampler.start()
            try:
                source(stop, received)
                if offline and (limit_message or not stop.is_set()):
                    put(("loaded", (mode, source_name, pending)), final=True)
                if limit_message:
                    message = limit_message
                elif stop.is_set():
                    message = "已取消读取" if offline else "已停止采集"
                else:
                    message = f"{mode}完成 · {count:,} 包"
            except Exception as exc:
                message = f"{'打开失败' if offline else '采集失败'} · {exc}"
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
                self._counts()
                self._select_default()
                break
            if kind == "owners":
                self.owner_samples.append(value)
                for flow_id, key in self.flow_keys.items():
                    self._match_owners(flow_id, key, (value,))
                continue
            if kind == "loaded":
                mode, name, packets = value
                self._reset_session()
                self.filter_var.set("全部")
                self.query_var.set("")
                self.mode_var.set(mode)
                self.session_var.set(name)
                self.process_note.set("经典 PCAP 没有进程 PID 元数据。可在回环实测或实时抓包时查看进程。")
                for packet, record in packets:
                    self._append(packet, record)
                changed = True
                continue
            if kind == "owner_error":
                self.process_note.set(value)
                continue
            self._append(*value)
            changed = True
        if changed:
            self._counts()
            if len(self.flow_labels) != self.flow_options_count:
                self.flow_box.configure(values=tuple(self.flow_labels))
                self.flow_options_count = len(self.flow_labels)
            if self.selected_flow is not None:
                self._flow_summary()
        if self.running and self.flow_owners and time.monotonic() >= self.next_process_refresh:
            self._refresh_processes()
            self.next_process_refresh = time.monotonic() + 0.35
        self.timer = self.root.after(35, self._poll)

    def _append(self, packet, record):
        self.records.append(record)
        self.wire_bytes += packet.length
        self.tracker.add(packet)
        if packet.flow_id is not None and len(self.flow_labels) < len(self.tracker.flows):
            flow = self.tracker.flows[packet.flow_id]
            self.flow_labels[f"#{flow.id}   {flow.endpoint_a}  ↔  {flow.endpoint_b}"] = flow.id
        if packet.flow_id is not None and self.collect_owners:
            # FlowTracker defines A as the first observed sender, even midstream.
            key = self.flow_keys.setdefault(packet.flow_id, (packet.src, packet.sport, packet.dst, packet.dport))
            self._match_owners(packet.flow_id, key, self.owner_samples)
        self.packets.append(packet)
        number = len(self.packets)
        if self._matches(packet):
            self._insert_packet(number, packet)
        if packet.flow_id is not None and packet.flow_id == self.selected_flow:
            self._insert_flow(number, packet)

    def _insert_packet(self, number, packet):
        self.packet_tree.insert("", "end", iid=str(number), tags=(packet.protocol,), values=(
            number, _time(packet.timestamp), _endpoint(packet.src, packet.sport), _endpoint(packet.dst, packet.dport),
            packet.protocol, packet.length, packet.info))
        self.displayed += 1

    def _matches(self, packet):
        if not packet.matches(self.filter_var.get()):
            return False
        words = self.query_var.get().casefold().split()
        if not words:
            return True
        text = " ".join((_endpoint(packet.src, packet.sport), _endpoint(packet.dst, packet.dport),
                         *packet.layers, packet.info)).casefold()
        return all(word in text for word in words)

    def schedule_filter(self, *_):
        if self.filter_timer is not None:
            self.root.after_cancel(self.filter_timer)
        self.filter_timer = self.root.after(130, self.apply_filter)

    def apply_filter(self, event=None):
        if self.filter_timer is not None:
            self.root.after_cancel(self.filter_timer)
            self.filter_timer = None
        previous = self.packet_tree.selection()
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.displayed = 0
        for number, packet in enumerate(self.packets, 1):
            if self._matches(packet):
                self._insert_packet(number, packet)
        if previous and self.packet_tree.exists(previous[0]):
            self.packet_tree.selection_set(previous[0])
            self.packet_tree.see(previous[0])
        elif self.displayed:
            self._select_default()
        self._selected()
        self._counts()

    def _select_default(self):
        if self.packet_tree.selection():
            return
        rows = self.packet_tree.get_children()
        if rows:
            number = next((i for i in rows if self.packets[int(i) - 1].protocol == "HTTP"), rows[0])
            self.packet_tree.selection_set(number)
            self.packet_tree.see(number)
            if number in rows[:5]:
                self.packet_tree.yview_moveto(0)
            self._selected()

    def _selected(self, event=None):
        selection = self.packet_tree.selection()
        self.field_tree.delete(*self.field_tree.get_children())
        packet = self.packets[int(selection[0]) - 1] if selection else None
        self.hex_text.configure(state="normal")
        self.hex_text.delete("1.0", "end")
        if packet is not None:
            self.selected_var.set(f"#{selection[0]}   {'  /  '.join(packet.layers)}")
            raw = self.records[int(selection[0]) - 1].data
            self.hex_text.insert("1.0", format_hex(raw))
            # Keep the selected protocol's own fields above the lower layers.
            fields = sorted(packet.details, key=lambda key: (
                not key.startswith(packet.protocol), key not in ("源端口", "目的端口", "源 IP", "目的 IP")))
            for field in fields:
                value = packet.details[field]
                self.field_tree.insert("", "end", values=(field, value))
        else:
            self.selected_var.set("尚未选中数据包")
        self.hex_text.configure(state="disabled")
        flow_id = packet.flow_id if packet else None
        if flow_id != self.selected_flow:
            self.selected_flow = flow_id
            self.flow_tree.delete(*self.flow_tree.get_children())
            if flow_id is not None:
                for number, other in enumerate(self.packets, 1):
                    if other.flow_id == flow_id:
                        self._insert_flow(number, other)
        self.flow_choice_var.set(next((name for name, fid in self.flow_labels.items() if fid == flow_id), ""))
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
        self._show_flow(int(selection[0]))

    def choose_flow(self, event=None):
        choice = self.flow_labels.get(self.flow_choice_var.get())
        if choice is not None:
            self._show_flow(choice)

    def inspect_flow_packet(self, event=None):
        selected = self.flow_tree.selection()
        if not selected:
            return
        number = selected[0]
        if not self.packet_tree.exists(number):
            self.query_var.set("")
            self.filter_var.set("TCP")
            self.apply_filter()
        self.packet_tree.selection_set(number)
        self.packet_tree.see(number)
        self._selected()
        self.notebook.select(0)

    def _show_flow(self, flow_id):
        numbers = [str(i) for i, pkt in enumerate(self.packets, 1) if pkt.flow_id == flow_id]
        number = next((n for n in numbers if self.packet_tree.exists(n)), None)
        if number is None:
            self.query_var.set("")
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
        if self.filter_timer is not None:
            self.root.after_cancel(self.filter_timer)
        self.root.withdraw()
        self._finish_close()

    def _finish_close(self):
        if self.worker is not None and self.worker.is_alive():
            self.root.after(30, self._finish_close)
        else:
            self.root.destroy()


if __name__ == "__main__":
    window = tk.Tk()
    app = SnifferApp(window)
    if len(sys.argv) == 2 and sys.argv[1] != "--sample":
        window.after_idle(app.open_capture, sys.argv[1])
    elif SAMPLE_PATH.is_file():
        window.after_idle(app.open_sample)
    window.mainloop()
