"""网络嗅探器的 Tk 布局；业务状态与数据更新由 SnifferApp 管理。"""

import tkinter as tk
from tkinter import ttk


NAVY = "#162b40"
TEAL = "#087c76"
INK = "#1c3247"
MUTED = "#4f687c"
BORDER = "#d6e1e8"
GROUND = "#edf2f5"
WHITE = "#ffffff"
FONT = "Microsoft YaHei UI"
PROTOCOLS = ("全部", "HTTP", "TCP", "UDP", "IPv4", "IPv6", "ICMP", "ICMPv6")


def _styles(root):
    style = ttk.Style(root)
    style.theme_use("clam")
    root.option_add("*Font", (FONT, 10))
    root.option_add("*TCombobox*Listbox.font", (FONT, 10))
    style.configure(".", font=(FONT, 10), foreground=INK)
    style.configure("TFrame", background=WHITE)
    style.configure("TLabel", background=WHITE, foreground=INK)
    style.configure("Note.TLabel", background=WHITE, foreground=MUTED, font=(FONT, 9))
    style.configure("TButton", background=WHITE, bordercolor=BORDER,
                    lightcolor=WHITE, darkcolor=WHITE, padding=(10, 5), focusthickness=1)
    style.map("TButton", background=[("active", "#e8eff3")], foreground=[("disabled", "#758997")])
    for name, bg, fg, border, hover in (
        ("Header", "#254057", "#f6fbff", "#456075", "#34536c"),
        ("Primary", TEAL, WHITE, TEAL, "#06665f"),
        ("Demo", "#e1f2ef", "#0a625b", "#b6d9d2", "#cce6e1"),
    ):
        button = name + ".TButton"
        style.configure(button, background=bg, foreground=fg, bordercolor=border,
                        lightcolor=bg, darkcolor=bg, padding=(11, 6))
        inactive_bg, inactive_fg = ("#24394b", "#9cadba") if name == "Header" else ("#e8edef", "#728491")
        style.map(button, background=[("disabled", inactive_bg), ("active", hover)],
                  foreground=[("disabled", inactive_fg)],
                  bordercolor=[("disabled", inactive_bg), ("active", border)],
                  lightcolor=[("disabled", inactive_bg), ("active", hover)],
                  darkcolor=[("disabled", inactive_bg), ("active", hover)])
    for control in ("TCombobox", "TEntry"):
        style.configure(control, fieldbackground=WHITE, bordercolor=BORDER, padding=(6, 4))
        style.map(control, fieldbackground=[("readonly", WHITE), ("disabled", "#f0f4f6")],
                  bordercolor=[("focus", TEAL)], selectbackground=[("!focus", WHITE)],
                  selectforeground=[("!focus", INK)])
    style.configure("Treeview", background=WHITE, fieldbackground=WHITE, foreground=INK,
                    borderwidth=0, rowheight=28, font=(FONT, 9))
    style.configure("Treeview.Heading", background="#e9eff3", foreground="#385267",
                    relief="flat", borderwidth=0, padding=(5, 5), font=(FONT, 9, "bold"))
    style.map("Treeview", background=[("selected", "#23636c")],
              foreground=[("selected", WHITE)])
    style.map("Treeview.Heading", background=[("active", "#e2eaf0")])
    style.configure("TNotebook", background=WHITE, borderwidth=0, tabmargins=(0, 0, 0, 2))
    style.configure("TNotebook.Tab", background="#e9eff3", foreground=MUTED,
                    padding=(8, 5), borderwidth=0, font=(FONT, 9))
    style.map("TNotebook.Tab", background=[("selected", "#d8eeea")],
              foreground=[("selected", "#0c655f")], expand=[("selected", (0, 0, 0, 0))])
    style.configure("TScrollbar", background="#dde6eb", troughcolor="#f5f8fa",
                    bordercolor="#f5f8fa", arrowcolor="#728797", arrowsize=12)
    style.configure("TPanedwindow", background=GROUND, sashthickness=8, sashrelief="flat")


def _icon(parent, name, background, color, size=32):
    canvas = tk.Canvas(parent, width=size, height=size, bg=background, highlightthickness=0)
    scale = size / 32

    def line(*points, width=2):
        canvas.create_line(*(p * scale for p in points), fill=color, width=width,
                           capstyle="round", joinstyle="round")

    if name == "pulse":
        line(2, 18, 8, 18, 11, 10, 15, 25, 21, 6, 24, 17, 30, 17, width=3)
    elif name == "packets":
        line(7, 11, 16, 6, 25, 11, 16, 16, 7, 11)
        line(7, 15, 16, 20, 25, 15)
        line(7, 19, 16, 24, 25, 19)
    elif name == "filter":
        line(6, 8, 26, 8, 19, 16, 19, 23, 14, 25, 14, 16, 6, 8)
    elif name == "flow":
        line(7, 11, 25, 11, 21, 7)
        line(25, 21, 7, 21, 11, 25)
    else:
        line(7, 23, 7, 16)
        line(13, 23, 13, 10)
        line(19, 23, 19, 13)
        line(25, 23, 25, 7)
    return canvas


def _card(parent):
    return tk.Frame(parent, background=WHITE, highlightbackground=BORDER, highlightthickness=1)


def _label(parent, text="", *, var=None, size=10, color=INK, bg=WHITE, bold=False, **kwargs):
    return tk.Label(parent, text=text, textvariable=var, font=(FONT, size, "bold" if bold else "normal"),
                    fg=color, bg=bg, borderwidth=0, anchor="w", **kwargs)


def _table(parent, columns):
    frame = ttk.Frame(parent)
    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)
    tree = ttk.Treeview(frame, columns=[col[0] for col in columns], show="headings", selectmode="browse",
                        height=6)
    for key, label, width, expandable in columns:
        tree.heading(key, text=label, anchor="w")
        tree.column(key, width=width, minwidth=width if not expandable else min(width, 65),
                    stretch=expandable, anchor="w")
    vertical = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
    horizontal = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
    tree.grid(row=0, column=0, sticky="nsew")
    vertical.grid(row=0, column=1, sticky="ns")
    horizontal.grid(row=1, column=0, sticky="ew")

    def scroll(bar, start, end):
        bar.set(start, end)
        fits = float(start) <= 0 and float(end) >= 1
        if fits and bar.winfo_manager():
            bar.grid_remove()
        elif not fits and not bar.winfo_manager():
            bar.grid()

    tree.configure(yscrollcommand=lambda a, b: scroll(vertical, a, b),
                   xscrollcommand=lambda a, b: scroll(horizontal, a, b))
    return frame, tree


def _heading(parent, title, var):
    head = tk.Frame(parent, bg=WHITE)
    head.pack(fill="x", padx=14, pady=(10, 8))
    _label(head, title, size=13, bold=True).pack(side="left")
    _label(head, var=var, size=9, color=MUTED).pack(side="right", padx=(8, 0))


def _wrapped(parent, variable):
    label = ttk.Label(parent, textvariable=variable, style="Note.TLabel", justify="left",
                      anchor="w", wraplength=310)
    label.pack(fill="x", pady=(5, 7))
    label.bind("<Configure>", lambda ev: label.configure(wraplength=max(60, ev.width - 4)))
    return label


def build_window(app):
    root = app.root
    _styles(root)
    root.title("网络嗅探器 · 实验 1A")
    width = min(1280, root.winfo_screenwidth() - 40)
    height = min(792, root.winfo_screenheight() - 90)
    root.geometry(f"{width}x{height}")
    root.minsize(min(880, width), min(570, height))
    root.configure(bg=GROUND)
    root.columnconfigure(0, weight=1)
    root.rowconfigure(1, weight=1)

    header = tk.Frame(root, bg=NAVY, padx=22, pady=12)
    header.grid(row=0, column=0, sticky="ew")
    icon = _icon(header, "pulse", NAVY, "#74d6c8", 38)
    icon.pack(side="left", padx=(0, 12))
    wordmark = tk.Frame(header, bg=NAVY)
    wordmark.pack(side="left")
    _label(wordmark, "网络嗅探器", size=17, bg=NAVY, color=WHITE, bold=True).pack(anchor="w")
    _label(wordmark, "软件与系统安全  /  实验 1A", size=9, bg=NAVY, color="#b4c8d6").pack(anchor="w")
    actions = tk.Frame(header, bg=NAVY)
    actions.pack(side="right")
    app.sample_button = ttk.Button(actions, text="打开样例", style="Header.TButton", command=app.open_sample)
    app.open_button = ttk.Button(actions, text="打开 PCAP…", style="Header.TButton", command=app.open_capture)
    app.export_button = ttk.Button(actions, text="导出全部包…", style="Header.TButton", command=app.export_capture)
    for button in (app.sample_button, app.open_button, app.export_button):
        button.pack(side="left", padx=(7, 0))

    body = tk.Frame(root, bg=GROUND, padx=16, pady=10)
    body.grid(row=1, column=0, sticky="nsew")
    body.columnconfigure(0, weight=1)
    body.rowconfigure(2, weight=1)
    capture = _card(body)
    capture.grid(row=0, column=0, sticky="ew")
    capture.columnconfigure(1, weight=1)
    _label(capture, "抓包接口", size=10, bold=True).grid(row=0, column=0, padx=(12, 9), pady=10)
    app.source_box = ttk.Combobox(capture, textvariable=app.source_name, state="readonly", width=20)
    app.source_box.grid(row=0, column=1, sticky="ew", pady=8)
    app.refresh_button = ttk.Button(capture, text="刷新", width=4, command=app.refresh_interfaces)
    app.refresh_button.grid(row=0, column=2, padx=(5, 10))
    app.start_button = ttk.Button(capture, text="开始抓包", style="Primary.TButton", command=app.start_capture)
    app.stop_button = ttk.Button(capture, text="停止", width=5, command=app.stop_capture)
    app.demo_button = ttk.Button(capture, text="回环实测", style="Demo.TButton", command=app.start_demo)
    app.start_button.grid(row=0, column=3, padx=(2, 5))
    app.stop_button.grid(row=0, column=4)
    app.demo_button.grid(row=0, column=5, padx=(10, 12))

    summary = tk.Frame(body, bg=GROUND)
    summary.grid(row=1, column=0, sticky="ew", pady=(8, 9))
    metrics = (
        ("捕获包数", app.total_var, "packets", "#e1edf8", "#3e6b96"),
        ("筛选后显示", app.visible_var, "filter", "#e0f1ec", "#2f7970"),
        ("TCP 连接", app.streams_var, "flow", "#eae7f6", "#766292"),
        ("捕获线长合计", app.bytes_var, "bytes", "#e8eef2", "#567084"),
    )
    for index, (caption, variable, symbol, back, front) in enumerate(metrics):
        summary.columnconfigure(index, weight=1, uniform="metric")
        metric = _card(summary)
        metric.grid(row=0, column=index, sticky="ew", padx=(0 if index == 0 else 6, 0))
        _icon(metric, symbol, back, front, 32).pack(side="left", padx=(12, 10), pady=8)
        content = tk.Frame(metric, bg=WHITE)
        content.pack(side="left", pady=(5, 6))
        _label(content, caption, size=9, color=MUTED).pack(anchor="w")
        tk.Label(content, textvariable=variable, font=("Segoe UI Semibold", 16), fg=INK,
                 bg=WHITE, borderwidth=0).pack(anchor="w")

    split = ttk.Panedwindow(body, orient="horizontal")
    split.grid(row=2, column=0, sticky="nsew")
    listing = _card(split)
    inspector = _card(split)
    split.add(listing, weight=3)
    split.add(inspector, weight=2)
    _heading(listing, "数据包列表", app.session_var)
    filters = tk.Frame(listing, bg=WHITE)
    filters.pack(fill="x", padx=12, pady=(0, 9))
    filters.columnconfigure(3, weight=1)
    _label(filters, "协议", size=9, color=MUTED).grid(row=0, column=0, padx=(0, 5))
    app.filter_box = ttk.Combobox(filters, textvariable=app.filter_var, values=PROTOCOLS,
                                  width=7, state="readonly")
    app.filter_box.grid(row=0, column=1)
    app.filter_box.bind("<<ComboboxSelected>>", app.apply_filter)
    _label(filters, "搜索", size=9, color=MUTED).grid(row=0, column=2, padx=(11, 5))
    search = ttk.Entry(filters, textvariable=app.query_var, width=16)
    search.grid(row=0, column=3, sticky="ew")
    app.search_entry = search
    placeholder = _label(search, "IP、端口或摘要", size=9, color="#667d8c", cursor="xterm")
    placeholder.bind("<Button-1>", lambda _: search.focus_set())
    clear = ttk.Button(filters, text="清空", width=4, command=lambda: app.query_var.set(""))
    clear.grid(row=0, column=4, padx=(4, 0))

    def update_hint(*_):
        query = app.query_var.get()
        if query:
            clear.grid()
        else:
            clear.grid_remove()
        if not query and root.focus_get() != search:
            placeholder.place(x=8, rely=.5, anchor="w")
        else:
            placeholder.place_forget()
    app.query_var.trace_add("write", update_hint)
    search.bind("<FocusIn>", lambda _: placeholder.place_forget())
    search.bind("<FocusOut>", lambda _: root.after_idle(update_hint))
    search.bind("<Escape>", lambda _: app.query_var.set(""))
    update_hint()

    package_frame, app.packet_tree = _table(listing, (
        ("number", "序号", 42, False), ("time", "时间", 100, False),
        ("src", "源端点", 97, True), ("dst", "目的端点", 97, True),
        ("protocol", "协议", 65, False), ("length", "线长 / B", 65, False),
        ("info", "摘要", 158, True),
    ))
    package_frame.pack(fill="both", expand=True)
    app.packet_tree.bind("<<TreeviewSelect>>", app._selected)
    for protocol, background, foreground in (
        ("TCP", "#f4f8fc", "#29465e"), ("HTTP", "#dff2eb", "#165746"),
        ("UDP", "#f2eefa", "#58466e"), ("ICMP", "#fbf1dd", "#6d5327"),
        ("ICMPv6", "#fbf1dd", "#6d5327"),
    ):
        app.packet_tree.tag_configure(protocol, background=background, foreground=foreground)
    app.empty_var = tk.StringVar(root)
    app.empty_panel = tk.Frame(app.packet_tree, bg=WHITE, padx=10, pady=10)
    _icon(app.empty_panel, "packets", WHITE, "#7096a7", 38).pack()
    _label(app.empty_panel, var=app.empty_var, size=10, color=MUTED, justify="center", wraplength=290).pack(pady=(6, 2))

    _heading(inspector, "报文检查器", app.selected_var)
    app.notebook = ttk.Notebook(inspector)
    app.notebook.pack(fill="both", expand=True, padx=6, pady=(1, 4))
    fields, app.field_tree = _table(app.notebook, (
        ("name", "字段", 124, True), ("value", "解析结果", 185, True),
    ))
    app.notebook.add(fields, text="字段解析")
    flow = ttk.Frame(app.notebook)
    app.notebook.add(flow, text="TCP 流追踪")
    flow_controls = ttk.Frame(flow)
    flow_controls.pack(fill="x", padx=4, pady=(5, 1))
    ttk.Label(flow_controls, text="连接", style="Note.TLabel").pack(side="left", padx=(0, 6))
    app.flow_box = ttk.Combobox(flow_controls, textvariable=app.flow_choice_var, state="readonly", width=12)
    app.flow_box.pack(side="left", fill="x", expand=True)
    app.flow_box.bind("<<ComboboxSelected>>", app.choose_flow)
    _wrapped(flow, app.flow_var)
    timeline, app.flow_tree = _table(flow, (
        ("number", "序号", 42, False), ("time", "时间", 100, False),
        ("src", "源端点", 136, True), ("dst", "目的端点", 136, True),
        ("length", "线长 / B", 64, False), ("info", "摘要", 182, True),
    ))
    timeline.pack(fill="both", expand=True)
    processes = ttk.Frame(app.notebook)
    app.notebook.add(processes, text="进程归属")
    process_controls = ttk.Frame(processes)
    process_controls.pack(fill="x", padx=4, pady=(5, 1))
    ttk.Label(process_controls, text="本机 PID", style="Note.TLabel").pack(side="left", padx=(0, 6))
    app.pid_box = ttk.Combobox(process_controls, textvariable=app.pid_var, width=8, state="readonly")
    app.pid_box.pack(side="left")
    app.pid_box.bind("<<ComboboxSelected>>", app._refresh_processes)
    ttk.Button(process_controls, text="查看报文", command=app._open_process_flow).pack(side="right")
    _wrapped(processes, app.process_note)
    pids, app.process_tree = _table(processes, (
        ("id", "流", 42, False), ("a", "端点 A", 138, True), ("a_pid", "PID A", 64, False),
        ("b", "端点 B", 138, True), ("b_pid", "PID B", 64, False), ("ab", "A→B 包", 65, False),
        ("ba", "B→A 包", 65, False), ("state", "状态", 100, True),
    ))
    pids.pack(fill="both", expand=True)
    app.process_tree.bind("<Double-1>", app._open_process_flow)
    raw = ttk.Frame(app.notebook)
    app.notebook.add(raw, text="原始字节")
    raw.rowconfigure(0, weight=1)
    raw.columnconfigure(0, weight=1)
    app.hex_text = tk.Text(raw, font=("Consolas", 10), fg=INK, bg="#f7fafb", wrap="none",
                           padx=8, pady=7, borderwidth=0, highlightthickness=0, width=10, height=5,
                           state="disabled")
    ybar = ttk.Scrollbar(raw, orient="vertical", command=app.hex_text.yview)
    xbar = ttk.Scrollbar(raw, orient="horizontal", command=app.hex_text.xview)
    app.hex_text.configure(yscrollcommand=ybar.set, xscrollcommand=xbar.set)
    app.hex_text.grid(row=0, column=0, sticky="nsew")
    ybar.grid(row=0, column=1, sticky="ns")
    xbar.grid(row=1, column=0, sticky="ew")

    status = tk.Frame(root, bg="#e1e9ee", padx=14, pady=4)
    status.grid(row=2, column=0, sticky="ew")
    _label(status, var=app.mode_var, size=9, bg="#e1e9ee", color="#145f60",
           bold=True).pack(side="left", padx=(0, 12))
    _label(status, var=app.status_var, size=9, bg="#e1e9ee", color=MUTED).pack(side="left", fill="x", expand=True)

    def first_split():
        if split.winfo_ismapped():
            split.sashpos(0, int(split.winfo_width() * .61))
    split.bind("<Map>", lambda _: root.after_idle(first_split))
    root.bind("<Control-o>", lambda _: app.open_button.invoke())
    root.bind("<Control-s>", lambda _: app.export_button.invoke())
    root.bind("<Control-f>", lambda _: search.focus_set())
