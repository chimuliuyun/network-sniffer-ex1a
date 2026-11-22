"""实验 1A 的原生 Tk 桌面布局。"""

import tkinter as tk
from tkinter import ttk


PROTOCOLS = ("全部", "HTTP", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ICMPv6")


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


def build_window(app):
    root = app.root
    root.title("网络嗅探器 · 实验 1A")
    root.geometry("1100x740")
    root.minsize(760, 550)
    if root.tk.call("tk", "windowingsystem") == "win32" and (
            root.winfo_screenwidth() < 1100 or root.winfo_screenheight() <= 800):
        root.state("zoomed")
    body = ttk.Frame(root, padding=(14, 12))
    body.pack(fill="both", expand=True)
    body.columnconfigure(0, weight=1)
    body.rowconfigure(2, weight=1)

    bar = ttk.Frame(body)
    bar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
    bar.columnconfigure(1, weight=1)
    ttk.Label(bar, text="抓包接口").grid(row=0, column=0, padx=(0, 7))
    app.source_box = ttk.Combobox(bar, textvariable=app.source_name, state="readonly", width=12)
    app.source_box.grid(row=0, column=1, sticky="ew")
    app.refresh_button = ttk.Button(bar, text="刷新接口", width=8, command=app.refresh_interfaces)
    app.start_button = ttk.Button(bar, text="开始抓包", width=8, command=app.start_capture)
    app.stop_button = ttk.Button(bar, text="停止", width=5, command=app.stop_capture)
    app.open_button = ttk.Button(bar, text="打开 PCAP…", width=11, command=app.open_capture)
    app.sample_button = ttk.Button(bar, text="打开样例", width=8, command=app.open_sample)
    app.export_button = ttk.Button(bar, text="导出全部包…", width=11, command=app.export_capture)
    app.demo_button = ttk.Button(bar, text="回环实测", width=8, command=app.start_demo)
    for col, button in enumerate((app.refresh_button, app.start_button, app.stop_button, app.open_button,
                                  app.sample_button, app.export_button, app.demo_button), start=2):
        button.grid(row=0, column=col, padx=(5, 0))

    filters = ttk.Frame(body)
    filters.grid(row=1, column=0, sticky="ew", pady=(0, 6))
    filters.columnconfigure(3, weight=1)
    ttk.Label(filters, text="协议筛选").grid(row=0, column=0, padx=(0, 7))
    app.filter_box = ttk.Combobox(filters, textvariable=app.filter_var, values=PROTOCOLS,
                                  width=12, state="readonly")
    app.filter_box.grid(row=0, column=1)
    app.filter_box.bind("<<ComboboxSelected>>", app.apply_filter)
    ttk.Label(filters, text="搜索").grid(row=0, column=2, padx=(12, 5))
    app.search_entry = ttk.Entry(filters, textvariable=app.query_var, width=12)
    app.search_entry.grid(row=0, column=3, sticky="ew")
    ttk.Button(filters, text="清空", width=5, command=lambda: app.query_var.set("")).grid(
        row=0, column=4, padx=(4, 10))
    ttk.Label(filters, textvariable=app.count_var).grid(row=0, column=5, sticky="e")

    split = ttk.Panedwindow(body, orient="vertical")
    split.grid(row=2, column=0, sticky="nsew")
    listing, app.packet_tree = _table(split, [
        ("number", "序号", 55, False), ("time", "时间", 110, False),
        ("src", "源端点", 155, True), ("dst", "目的端点", 155, True),
        ("protocol", "协议", 72, False), ("length", "线长 / B", 76, False),
        ("info", "摘要", 310, True),
    ])
    split.add(listing, weight=3)
    app.packet_tree.bind("<<TreeviewSelect>>", app._selected)
    for protocol, background, foreground in (
        ("TCP", "#f4f8fc", "#29465e"), ("HTTP", "#dff2eb", "#165746"),
        ("UDP", "#f2eefa", "#58466e"), ("ICMP", "#fbf1dd", "#6d5327"),
        ("ICMPv6", "#fbf1dd", "#6d5327"),
    ):
        app.packet_tree.tag_configure(protocol, background=background, foreground=foreground)
    app.empty_var = tk.StringVar(root)
    app.empty_panel = ttk.Label(app.packet_tree, textvariable=app.empty_var, padding=(8, 4))

    app.notebook = ttk.Notebook(split)
    split.add(app.notebook, weight=2)
    fields, app.field_tree = _table(app.notebook, [
        ("name", "字段", 210, False), ("value", "解析结果", 680, True),
    ])
    app.notebook.add(fields, text="字段解析")
    flow = ttk.Frame(app.notebook, padding=(5, 3))
    app.notebook.add(flow, text="TCP 流追踪")
    flow_controls = ttk.Frame(flow)
    flow_controls.pack(fill="x")
    ttk.Label(flow_controls, text="连接").pack(side="left", padx=(0, 6))
    app.flow_box = ttk.Combobox(flow_controls, textvariable=app.flow_choice_var, state="readonly")
    app.flow_box.pack(side="left", fill="x", expand=True)
    app.flow_box.bind("<<ComboboxSelected>>", app.choose_flow)
    summary = ttk.Label(flow, textvariable=app.flow_var, justify="left", wraplength=700)
    summary.pack(fill="x", pady=(1, 4))
    timeline, app.flow_tree = _table(flow, [
        ("number", "包序号", 60, False), ("time", "时间", 110, False),
        ("src", "源端点", 175, True), ("dst", "目的端点", 175, True),
        ("length", "线长 / B", 76, False), ("info", "摘要", 270, True),
    ])
    timeline.pack(fill="both", expand=True)

    processes = ttk.Frame(app.notebook, padding=(5, 3))
    app.notebook.add(processes, text="进程归属")
    controls = ttk.Frame(processes)
    controls.pack(fill="x", pady=(1, 4))
    ttk.Label(controls, text="本机 PID").pack(side="left", padx=(0, 5))
    app.pid_box = ttk.Combobox(controls, textvariable=app.pid_var, width=8, state="readonly")
    app.pid_box.pack(side="left")
    app.pid_box.bind("<<ComboboxSelected>>", app._refresh_processes)
    ttk.Button(controls, text="查看报文", command=app._open_process_flow).pack(side="right")
    process_note = ttk.Label(processes, textvariable=app.process_note, anchor="w", wraplength=700)
    process_note.pack(fill="x", pady=(0, 3))
    pids, app.process_tree = _table(processes, [
        ("id", "流", 48, False), ("a", "端点 A", 185, True), ("a_pid", "PID A", 74, False),
        ("b", "端点 B", 185, True), ("b_pid", "PID B", 74, False),
        ("ab", "A→B 包", 70, False), ("ba", "B→A 包", 70, False), ("state", "状态", 95, True),
    ])
    pids.pack(fill="both", expand=True)
    app.process_tree.bind("<Double-1>", app._open_process_flow)

    raw = ttk.Frame(app.notebook, padding=(5, 3))
    app.notebook.add(raw, text="原始字节")
    raw.columnconfigure(0, weight=1)
    raw.rowconfigure(1, weight=1)
    ttk.Label(raw, textvariable=app.selected_var).grid(row=0, column=0, sticky="w", pady=(0, 3))
    app.hex_text = tk.Text(raw, wrap="none", font="TkFixedFont", state="disabled", width=10, height=5)
    ybar = ttk.Scrollbar(raw, orient="vertical", command=app.hex_text.yview)
    xbar = ttk.Scrollbar(raw, orient="horizontal", command=app.hex_text.xview)
    app.hex_text.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
    app.hex_text.grid(row=1, column=0, sticky="nsew")
    ybar.grid(row=1, column=1, sticky="ns")
    xbar.grid(row=2, column=0, sticky="ew")

    footer = ttk.Frame(body)
    footer.grid(row=3, column=0, sticky="ew", pady=(7, 0))
    footer.columnconfigure(0, weight=1)
    status = ttk.Label(footer, textvariable=app.status_var, anchor="w", wraplength=700)
    status.grid(row=0, column=0, sticky="ew")
    ttk.Label(footer, textvariable=app.session_var).grid(row=0, column=1, padx=(10, 0))
    for label in (summary, process_note, status):
        label.bind("<Configure>", lambda event: event.widget.configure(wraplength=max(1, event.width - 4)))
    app.search_entry.bind("<Escape>", lambda _: app.query_var.set(""))
    root.bind("<Control-o>", lambda _: app.open_button.invoke())
    root.bind("<Control-s>", lambda _: app.export_button.invoke())
    root.bind("<Control-f>", lambda _: app.search_entry.focus_set())
