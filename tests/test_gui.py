"""用仓库中实抓的 34 包样例验证桌面界面的典型操作。"""

from pathlib import Path
import sys
import tempfile
import time
import tkinter as tk
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from capture import CaptureError, Interface
from gui import SAMPLE_PATH, SnifferApp


class InspectorTests(unittest.TestCase):
    def setUp(self):
        try:
            self.window = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"需要图形显示环境：{exc}")
        self.window.withdraw()
        with patch("gui.list_interfaces", return_value=[]):
            self.app = SnifferApp(self.window)
        self.addCleanup(self.app.close)
        self.app.open_sample()
        self.finish_read()

    def finish_read(self):
        deadline = time.monotonic() + 5
        while self.app.running and time.monotonic() < deadline:
            self.window.update()
            time.sleep(.01)
        self.assertFalse(self.app.running)

    def test_search_bytes_and_flow_navigation(self):
        app = self.app
        self.assertEqual(len(app.packets), 34)
        self.assertEqual(app.mode_var.get(), "实验样例")
        app.filter_var.set("HTTP")
        app.query_var.set("62045 GET /experiment-1a")
        app.apply_filter()
        self.assertEqual(app.displayed, 1)
        self.assertIn("47 45 54", app.hex_text.get("1.0", "end"))
        app.query_var.set("无匹配")
        app.apply_filter()
        self.assertEqual(app.displayed, 0)
        app.flow_choice_var.set(app.flow_box["values"][1])
        app.choose_flow()
        self.assertEqual(app.selected_flow, 2)
        self.assertEqual(len(app.flow_tree.get_children()), 13)
        item = app.flow_tree.get_children()[2]
        app.flow_tree.selection_set(item)
        app.inspect_flow_packet()
        self.assertEqual(app.packet_tree.selection(), (item,))
        self.assertEqual(app.notebook.index("current"), 0)

    def test_offline_sample_keeps_driver_hint_until_refresh(self):
        app = self.app
        with patch("gui.list_interfaces", side_effect=CaptureError("未找到 Npcap 运行库")):
            app.refresh_interfaces()
        app.open_sample()
        self.finish_read()
        self.assertIn("34 包", app.status_var.get())
        self.assertIn("Npcap", app.status_var.get())
        self.assertTrue(app.start_button.instate(["disabled"]))
        adapter = Interface(r"\Device\NPF_Loopback", "Adapter for loopback capture")
        with patch("gui.list_interfaces", return_value=[adapter]):
            app.refresh_interfaces()
        self.assertEqual(app.interface_notice, "")
        self.assertFalse(app.demo_button.instate(["disabled"]))
        self.assertEqual(len(app.records), 34)

    def test_export_preserves_full_capture_and_failed_open_preserves_session(self):
        app = self.app
        original = app.records.copy()
        app.filter_var.set("HTTP")
        app.apply_filter()
        self.assertEqual(app.displayed, 4)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "会话.pcap"
            app.export_capture(path)
            app.open_capture(path)
            self.finish_read()
            self.assertEqual(app.records, original)
            broken = Path(folder) / "截断.pcap"
            broken.write_bytes(SAMPLE_PATH.read_bytes()[:-1])
            app.open_capture(broken)
            self.finish_read()
            self.assertIn("打开失败", app.status_var.get())
            self.assertEqual(app.session_var.get(), path.name)
            self.assertEqual(app.records, original)
