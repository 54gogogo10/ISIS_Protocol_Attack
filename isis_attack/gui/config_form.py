"""动态配置表单 — 根据攻击类型动态生成参数字段。"""

import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Any
from .styles import FONT_LABEL, FONT_ENTRY, PAD_FORM, PAD_OUTER, SECTION_GAP


# =====================================================================
# 路由条目编辑器
# =====================================================================

class RoutesHolder:
    def __init__(self, routes=None):
        self.routes: list[dict] = list(routes) if routes else []

    def get(self) -> list[dict]:
        return list(self.routes)

    def set(self, value):
        if isinstance(value, str):
            try:
                self.routes = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                self.routes = []
        elif isinstance(value, list):
            self.routes = list(value)


class RoutesEditor(tk.Toplevel):
    def __init__(self, parent, holder: RoutesHolder):
        super().__init__(parent)
        self.title("编辑伪造路由条目")
        self.geometry("600x360")
        self.resizable(True, True)
        self.transient(parent)
        self.grab_set()
        self._holder = holder
        self._routes: list[dict] = [r.copy() for r in holder.routes]
        self._build_ui()
        self._refresh()

    def _build_ui(self):
        cols = ("network", "mask", "metric")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", selectmode="browse", height=10)
        for col, hdr, w in [("network", "目标网络", 160), ("mask", "掩码", 130), ("metric", "Metric", 80)]:
            self._tree.heading(col, text=hdr)
            self._tree.column(col, width=w, anchor="center")
        self._tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10, 0))

        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, padx=10, pady=8)
        ttk.Button(bar, text="添加", command=self._on_add).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="编辑", command=self._on_edit).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="删除", command=self._on_delete).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="保存", command=self._on_save).pack(side=tk.RIGHT, padx=2)
        ttk.Button(bar, text="取消", command=self.destroy).pack(side=tk.RIGHT, padx=2)

    def _refresh(self):
        for row in self._tree.get_children():
            self._tree.delete(row)
        for r in self._routes:
            self._tree.insert("", tk.END, values=(r.get("network", ""), r.get("mask", "255.255.255.0"), r.get("metric", 10)))

    def _on_add(self):
        dlg = _RouteDialog(self, None)
        if dlg.result:
            self._routes.append(dlg.result)
            self._refresh()

    def _on_edit(self):
        sel = self._tree.selection()
        if sel:
            idx = self._tree.index(sel[0])
            dlg = _RouteDialog(self, self._routes[idx])
            if dlg.result:
                self._routes[idx] = dlg.result
                self._refresh()

    def _on_delete(self):
        sel = self._tree.selection()
        if sel:
            idx = self._tree.index(sel[0])
            self._tree.delete(sel[0])
            del self._routes[idx]

    def _on_save(self):
        self._holder.routes = list(self._routes)
        self.destroy()


class _RouteDialog(tk.Toplevel):
    def __init__(self, parent, existing: dict | None):
        super().__init__(parent)
        self.title("编辑路由" if existing else "添加路由")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()
        self.result: dict | None = None
        r = existing or {"network": "10.0.0.0", "mask": "255.255.255.0", "metric": 10}
        self._vars: dict[str, tk.StringVar] = {}
        row = 0
        for label, key, val in [("目标网络:", "network", r.get("network", "")),
                                 ("掩码:", "mask", r.get("mask", "255.255.255.0")),
                                 ("Metric:", "metric", str(r.get("metric", 10)))]:
            ttk.Label(self, text=label, font=FONT_LABEL).grid(row=row, column=0, sticky=tk.W, padx=10, pady=4)
            v = tk.StringVar(value=str(val))
            ttk.Entry(self, textvariable=v, font=FONT_ENTRY, width=24).grid(row=row, column=1, sticky=tk.EW, padx=10, pady=4)
            self._vars[key] = v
            row += 1
        bar = ttk.Frame(self)
        bar.grid(row=row, column=0, columnspan=2, pady=10)
        ttk.Button(bar, text="确定", command=self._on_ok).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="取消", command=self.destroy).pack(side=tk.LEFT, padx=4)
        self.wait_window()

    def _on_ok(self):
        try:
            self.result = {"network": self._vars["network"].get(),
                           "mask": self._vars["mask"].get(),
                           "metric": int(self._vars["metric"].get())}
        except ValueError:
            self.result = None
        self.destroy()


def get_network_interfaces() -> list[str]:
    """获取本机网卡可读名称。Windows 用 Scapy/Npcap，Linux 用 socket。"""
    # Windows: Scapy IFACES 提供 Npcap 可读名称
    try:
        from scapy.all import IFACES
        names = sorted(set(
            d.description for d in IFACES.data.values()
            if d.description and d.description != "Unknown"
        ))
        if names:
            return names
    except Exception:
        pass
    # Linux / fallback
    try:
        import socket
        return [name for _, name in socket.if_nameindex()]
    except Exception:
        pass
    return ["eth0"]


# =====================================================================
# 字段元数据
# =====================================================================

FIELD_META: dict[str, dict] = {
    # -- 通用参数 --
    "iface":          {"widget": "iface",   "label": "网卡接口"},
    "target":         {"widget": "entry",   "label": "目标 MAC", "default": "01:80:C2:00:00:14"},
    "mode":           {"widget": "radio",   "label": "攻击模式", "choices": ["passive", "active"]},
    "sniff_mode":     {"widget": "radio",   "label": "嗅探模式", "choices": ["hub", "arp_spoof"]},
    "sys_id":         {"widget": "entry",   "label": "伪装 System ID", "default": "1921.6800.1001"},
    "area_addr":      {"widget": "entry",   "label": "Area 地址", "default": "49.0001"},
    "level":          {"widget": "combo",   "label": "IS-IS 级别", "choices": ["1", "2"], "default": "1", "type": int},
    "sniff_duration": {"widget": "spinbox", "label": "嗅探时长(秒)", "from_": 1, "to": 3600, "default": 30},
    "arp_target_a":   {"widget": "entry",   "label": "ARP 欺骗目标 A"},
    "arp_target_b":   {"widget": "entry",   "label": "ARP 欺骗目标 B"},
    "arp_interval":   {"widget": "spinbox", "label": "ARP 间隔(秒)", "from_": 1, "to": 60, "default": 2},
    "packet_rate":    {"widget": "spinbox", "label": "发包速率(pps)", "from_": 1, "to": 10000, "default": 10},
    "max_packets":    {"widget": "spinbox", "label": "最大发包数(0=不限)", "from_": 0, "to": 1000000, "default": 0},
    "verbose":        {"widget": "check",   "label": "详细输出"},

    # -- IIH (Hello) 专属 --
    "hello_interval": {"widget": "spinbox", "label": "Hello 间隔(秒)", "from_": 1, "to": 65535, "default": 10},
    "hold_timer":     {"widget": "spinbox", "label": "Hold 计时器(秒)", "from_": 1, "to": 65535, "default": 30},
    "priority":       {"widget": "spinbox", "label": "优先级", "from_": 0, "to": 127, "default": 64},
    "auth_type":      {"widget": "combo",   "label": "认证类型", "choices": ["none", "plain", "md5"], "default": "none"},
    "auth_key":       {"widget": "entry",   "label": "认证密钥"},
    "circ_id":        {"widget": "spinbox", "label": "电路 ID", "from_": 0, "to": 255, "default": 0},

    # -- LSP 专属 --
    "lsp_id":            {"widget": "entry",   "label": "LSP ID"},
    "sequence":          {"widget": "entry",   "label": "序列号 (hex)", "default": "0x1", "type": int},
    "remaining_lifetime":{"widget": "spinbox", "label": "Remaining Lifetime(s)", "from_": 0, "to": 65535, "default": 1200},
    "metric":            {"widget": "spinbox", "label": "Metric", "from_": 0, "to": 16777215, "default": 10},
    "network_addr":      {"widget": "entry",   "label": "网络地址", "default": "10.0.0.0"},
    "network_mask":      {"widget": "entry",   "label": "网络掩码", "default": "255.255.255.0"},

    # -- DoS 专属 --
    "duration":            {"widget": "spinbox", "label": "持续时间(秒)", "from_": 1, "to": 86400, "default": 60},
    "thread_count":        {"widget": "spinbox", "label": "并发线程数", "from_": 1, "to": 100, "default": 1},
    "lsp_change_interval": {"widget": "spinbox", "label": "LSP 变化间隔(秒)", "from_": 1, "to": 3600, "default": 2},
    "lsp_count":           {"widget": "spinbox", "label": "注入 LSP 数量", "from_": 1, "to": 100000, "default": 1000},

    # -- LSP 专属补充 --
    "overload_bit":      {"widget": "check", "label": "设置 Overload Bit"},
    "external_routes":   {"widget": "routes", "label": "伪造路由条目"},

    # -- MITM 专属 --
    "target_a":    {"widget": "entry",   "label": "路由器 A IP"},
    "target_b":    {"widget": "entry",   "label": "路由器 B IP"},
    "action":      {"widget": "combo",   "label": "操作类型", "choices": ["drop", "modify", "forward", "inject"], "default": "modify"},
    "modify_rules":{"widget": "entry",   "label": "修改规则 (JSON)"},

    # -- Replay 专属 --
    "capture_file":   {"widget": "entry",   "label": "捕获文件路径"},
    "replay_loop":    {"widget": "check",   "label": "循环重放"},
    "replay_interval":{"widget": "spinbox", "label": "重放间隔(秒)", "from_": 1, "to": 3600, "default": 5},
    "modify_fields":  {"widget": "entry",   "label": "修改字段 (JSON)"},
}

COMMON_FIELDS = [
    "iface", "target", "mode", "sniff_mode", "sys_id", "area_addr", "level",
    "sniff_duration", "arp_target_a", "arp_target_b", "arp_interval",
    "packet_rate", "max_packets", "verbose",
]

SPECIFIC_FIELDS: dict[str, list[str]] = {
    "iih-inject":       ["hello_interval", "hold_timer", "priority",
                         "circ_id", "auth_type", "auth_key"],
    "adjacency-break":  ["hello_interval", "hold_timer", "priority"],
    "dis-hijack":       ["hello_interval", "hold_timer", "priority"],
    "route-inject":     ["lsp_id", "sequence", "remaining_lifetime", "metric",
                         "network_addr", "network_mask", "external_routes",
                         "auth_type", "auth_key"],
    "max-seq":          ["lsp_id", "sequence", "remaining_lifetime",
                         "metric", "network_addr", "network_mask"],
    "purge-lsp":        ["lsp_id", "sequence", "remaining_lifetime",
                         "metric", "network_addr", "network_mask"],
    "fight-back":       ["lsp_id", "sequence", "remaining_lifetime",
                         "metric", "network_addr", "network_mask"],
    "overload-bit":     ["lsp_id", "sequence", "remaining_lifetime", "overload_bit",
                         "metric", "network_addr", "network_mask"],
    "flood":            ["duration", "thread_count"],
    "spf-recalc":       ["duration", "lsp_change_interval"],
    "db-overflow":      ["duration", "lsp_count"],
    "mitm":             ["target_a", "target_b", "action", "modify_rules"],
    "replay":           ["capture_file", "replay_loop", "replay_interval", "modify_fields"],
}


# =====================================================================
# 数值构建
# =====================================================================

def build_config_dict(widgets: dict, meta: dict[str, dict]) -> dict[str, Any]:
    result = {}
    for name, w in widgets.items():
        try:
            raw = w.get()
        except Exception:
            continue
        if raw == "" or raw is None:
            continue
        m = meta.get(name, {})
        wtype = m.get("widget", "entry")
        if wtype == "routes":
            result[name] = raw  # raw is list[dict]
            continue
        target_type = m.get("type", None)
        if wtype == "spinbox":
            try:
                result[name] = int(raw)
            except ValueError:
                result[name] = raw
        elif wtype == "check":
            result[name] = bool(raw)
        elif target_type is int:
            try:
                result[name] = int(str(raw), 0)
            except ValueError:
                result[name] = str(raw)
        else:
            result[name] = str(raw)
    return result


# =====================================================================
# 配置表单
# =====================================================================

class ConfigForm(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        self._attack_name: str | None = None
        self._widgets: dict[str, Any] = {}
        self._sniff_var: tk.StringVar | None = None
        self._preview_cb = None

        # 滚动容器
        self._canvas = tk.Canvas(self, highlightthickness=0)
        self._scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=self._canvas.yview)
        self._scroll_frame = ttk.Frame(self._canvas)

        self._scroll_frame.bind("<Configure>",
            lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.create_window((0, 0), window=self._scroll_frame, anchor="nw")
        self._canvas.configure(yscrollcommand=self._scrollbar.set)

        self._canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self._common_frame = ttk.LabelFrame(self._scroll_frame, text="通用参数", padding=8)
        self._common_frame.pack(fill=tk.X, padx=PAD_OUTER, pady=(PAD_OUTER, 0))

        self._arp_frame = ttk.LabelFrame(self._scroll_frame, text="ARP 欺骗设置", padding=8)
        self._specific_frame = ttk.LabelFrame(self._scroll_frame, text="攻击专属参数", padding=8)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_attack(self, attack_name: str):
        self._attack_name = attack_name
        self._widgets.clear()

        for w in (self._common_frame, self._arp_frame, self._specific_frame):
            for child in w.winfo_children():
                child.destroy()

        self._build_common()
        self._build_arp()
        self._build_specific(attack_name)

        self._common_frame.pack(fill=tk.X, padx=PAD_OUTER, pady=(PAD_OUTER, 0))
        self._specific_frame.pack(fill=tk.X, padx=PAD_OUTER, pady=(SECTION_GAP, 0))
        self._toggle_arp()

    def get_config_dict(self) -> dict:
        return build_config_dict(self._widgets, FIELD_META)

    def set_config_dict(self, data: dict):
        for name, value in data.items():
            w = self._widgets.get(name)
            if w is None:
                continue
            try:
                if hasattr(w, "set"):
                    w.set(str(value))
                elif hasattr(w, "delete"):
                    w.delete(0, tk.END)
                    w.insert(0, str(value))
            except Exception:
                pass

    def format_preview(self) -> str:
        return _format_isis_preview(self)

    def set_preview_callback(self, cb):
        """设置路由变化后的预览刷新回调。"""
        self._preview_cb = cb

    def export_pcap(self) -> bool:
        """导出当前构造的报文为 pcap 文件。"""
        path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("pcap files", "*.pcap"), ("All files", "*.*")],
            title="导出构造的报文为 pcap",
        )
        if not path:
            return False
        try:
            from scapy.utils import wrpcap
            raw = _build_raw_isis_packet(self)
            if raw:
                wrpcap(path, raw)
                return True
        except Exception as e:
            messagebox.showerror("导出失败", str(e))
        return False

    def auto_fill_from_packet(self, pkt: dict):
        """从捕获的 ISIS 报文字段自动填充表单参数。"""
        def _set(key, value):
            if key in self._widgets and value is not None and value != "":
                try:
                    w = self._widgets[key]
                    if hasattr(w, "set"):
                        w.set(str(value))
                    elif hasattr(w, "delete"):
                        w.delete(0, tk.END)
                        w.insert(0, str(value))
                except Exception:
                    pass
        _set("sys_id", pkt.get("sys_id"))
        _set("target", pkt.get("dst_mac"))
        if "area_addr" in pkt:
            _set("area_addr", pkt["area_addr"])
        if "metric" in pkt:
            _set("metric", pkt["metric"])
        if "sequence" in pkt:
            _set("sequence", f"0x{pkt['sequence']:08X}")
        if "lifetime" in pkt:
            _set("remaining_lifetime", pkt["lifetime"])
        if "ip_reach" in pkt:
            ip_reach = pkt["ip_reach"]
            if "/" in str(ip_reach):
                net, mask = str(ip_reach).split("/", 1)
                _set("network_addr", net)
                # Convert CIDR to mask
                try:
                    bits = int(mask)
                    mask_int = (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF
                    mask_str = ".".join(str((mask_int >> (8 * n)) & 0xFF) for n in range(3, -1, -1))
                    _set("network_mask", mask_str)
                except ValueError:
                    pass

    # ------------------------------------------------------------------
    # Build helpers
    # ------------------------------------------------------------------

    def _build_common(self):
        _build_field_row(self._common_frame, "iface", 0, self)
        _build_field_row(self._common_frame, "target", 1, self)
        _build_field_row(self._common_frame, "sys_id", 2, self)
        _build_field_row(self._common_frame, "area_addr", 3, self)
        _build_field_row(self._common_frame, "level", 4, self)

        # mode radiobutton
        f_mode = ttk.Frame(self._common_frame)
        f_mode.grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=PAD_FORM)
        ttk.Label(f_mode, text="攻击模式:", font=FONT_LABEL).pack(side=tk.LEFT)
        mode_var = tk.StringVar(value="passive")
        ttk.Radiobutton(f_mode, text="旁路", variable=mode_var, value="passive").pack(side=tk.LEFT, padx=4)
        ttk.Radiobutton(f_mode, text="主动", variable=mode_var, value="active").pack(side=tk.LEFT, padx=4)
        self._widgets["mode"] = mode_var

        # sniff_mode radiobutton
        f_sniff = ttk.Frame(self._common_frame)
        f_sniff.grid(row=6, column=0, columnspan=2, sticky=tk.W, pady=PAD_FORM)
        ttk.Label(f_sniff, text="嗅探模式:", font=FONT_LABEL).pack(side=tk.LEFT)
        sniff_var = tk.StringVar(value="hub")
        ttk.Radiobutton(f_sniff, text="集线器", variable=sniff_var, value="hub").pack(side=tk.LEFT, padx=4)
        ttk.Radiobutton(f_sniff, text="ARP 欺骗", variable=sniff_var, value="arp_spoof").pack(side=tk.LEFT, padx=4)
        self._widgets["sniff_mode"] = sniff_var
        self._sniff_var = sniff_var
        sniff_var.trace_add("write", lambda *_: self._toggle_arp())

        _build_field_row(self._common_frame, "sniff_duration", 7, self)
        _build_field_row(self._common_frame, "packet_rate", 8, self)
        _build_field_row(self._common_frame, "max_packets", 9, self)

        f_verbose = ttk.Frame(self._common_frame)
        f_verbose.grid(row=10, column=0, columnspan=2, sticky=tk.W, pady=PAD_FORM)
        verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(f_verbose, text="详细输出", variable=verbose_var).pack(side=tk.LEFT)
        self._widgets["verbose"] = verbose_var

    def _build_arp(self):
        _build_field_row(self._arp_frame, "arp_target_a", 0, self)
        _build_field_row(self._arp_frame, "arp_target_b", 1, self)
        _build_field_row(self._arp_frame, "arp_interval", 2, self)

    def _build_specific(self, attack_name: str):
        fields = SPECIFIC_FIELDS.get(attack_name, [])
        for i, name in enumerate(fields):
            _build_field_row(self._specific_frame, name, i, self)
        # Attack-specific default overrides
        self._apply_overrides(attack_name)
        # Auto-compute fields
        self._auto_fill_lsp_id()
        self._auto_hold_timer()

    _OVERRIDES: dict[str, dict] = {
        "max-seq":      {"sequence": "0xFFFFFFFF"},
        "purge-lsp":    {"remaining_lifetime": "0"},
        "overload-bit": {"overload_bit": True},
        "dis-hijack":   {"priority": "127"},
        "iih-inject":   {"priority": "127"},
    }

    def _apply_overrides(self, attack_name: str):
        for key, value in self._OVERRIDES.get(attack_name, {}).items():
            w = self._widgets.get(key)
            if w is None:
                continue
            try:
                if isinstance(value, bool):
                    w.set(value)
                elif hasattr(w, "set"):
                    w.set(str(value))
                elif hasattr(w, "delete"):
                    w.delete(0, tk.END)
                    w.insert(0, str(value))
            except Exception:
                pass

    def _auto_fill_lsp_id(self):
        """根据 System ID 自动生成 LSP ID (xxxx.xxxx.xxxx.00-00)。"""
        if "lsp_id" not in self._widgets:
            return
        lsid_var = self._widgets["lsp_id"]
        current = lsid_var.get().strip() if hasattr(lsid_var, "get") else ""
        if current:  # 用户已手动填写则保留
            return
        if "sys_id" in self._widgets:
            sys_id = self._widgets["sys_id"].get().strip()
            if sys_id:
                lsid_var.set(f"{sys_id}.00-00")
        # 监听 sys_id 变化自动更新 lsp_id
        if "sys_id" in self._widgets:
            sys_var = self._widgets["sys_id"]
            def _on_sys_change(*args):
                if "lsp_id" in self._widgets:
                    cur = self._widgets["lsp_id"].get().strip()
                    new_sys = sys_var.get().strip()
                    if not cur or cur.startswith("1921.6800.1001") or cur == f"{new_sys}.00-00":
                        self._widgets["lsp_id"].set(f"{new_sys}.00-00")
            sys_var.trace_add("write", _on_sys_change)

    def _auto_hold_timer(self):
        """自动计算 Hold Timer = 3 × Hello Interval。"""
        if "hold_timer" not in self._widgets or "hello_interval" not in self._widgets:
            return
        hi_var = self._widgets["hello_interval"]
        ht_var = self._widgets["hold_timer"]
        def _on_hello_change(*args):
            try:
                hi = int(hi_var.get())
                ht_var.set(str(hi * 3))
            except (ValueError, tk.TclError):
                pass
        hi_var.trace_add("write", _on_hello_change)
        # Set initial value
        try:
            hi = int(hi_var.get())
            ht_var.set(str(hi * 3))
        except (ValueError, tk.TclError):
            pass

    def _toggle_arp(self):
        if self._sniff_var and self._sniff_var.get() == "arp_spoof":
            self._arp_frame.pack(fill=tk.X, padx=PAD_OUTER, pady=(SECTION_GAP, 0))
        else:
            self._arp_frame.pack_forget()


# =====================================================================
# 字段行构建
# =====================================================================

def _build_field_row(parent: ttk.Frame, field_name: str, row: int, form: ConfigForm):
    meta = FIELD_META.get(field_name, {})
    label_text = meta.get("label", field_name)
    wtype = meta.get("widget", "entry")

    lbl = ttk.Label(parent, text=label_text + ":", font=FONT_LABEL)
    lbl.grid(row=row, column=0, sticky=tk.W, padx=(0, 6), pady=PAD_FORM)

    if wtype == "iface":
        ifaces = get_network_interfaces()
        var = tk.StringVar(value=ifaces[0] if ifaces else "eth0")
        w = ttk.Combobox(parent, textvariable=var, values=ifaces, font=FONT_ENTRY, width=30)
        w.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        form._widgets[field_name] = var

    elif wtype == "entry":
        default = meta.get("default", "")
        var = tk.StringVar(value=str(default))
        w = ttk.Entry(parent, textvariable=var, font=FONT_ENTRY, width=32)
        w.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        form._widgets[field_name] = var

    elif wtype == "spinbox":
        from_ = meta.get("from_", 0)
        to = meta.get("to", 65535)
        default = meta.get("default", from_)
        var = tk.StringVar(value=str(default))
        w = ttk.Spinbox(parent, from_=from_, to=to, textvariable=var, font=FONT_ENTRY, width=30)
        w.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        form._widgets[field_name] = var

    elif wtype == "combo":
        choices = meta.get("choices", [])
        default = meta.get("default", choices[0] if choices else "")
        var = tk.StringVar(value=str(default))
        w = ttk.Combobox(parent, textvariable=var, values=choices, font=FONT_ENTRY, width=30, state="readonly")
        w.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        form._widgets[field_name] = var

    elif wtype == "check":
        var = tk.BooleanVar(value=False)
        w = ttk.Checkbutton(parent, variable=var)
        w.grid(row=row, column=1, sticky=tk.W, pady=PAD_FORM)
        form._widgets[field_name] = var

    elif wtype == "radio":
        choices = meta.get("choices", [])
        default = meta.get("default", choices[0] if choices else "")
        var = tk.StringVar(value=default)
        f = ttk.Frame(parent)
        f.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        for c in choices:
            ttk.Radiobutton(f, text=c, variable=var, value=c).pack(side=tk.LEFT, padx=4)
        form._widgets[field_name] = var

    elif wtype == "routes":
        holder = RoutesHolder()
        count_var = tk.StringVar(value="未配置")
        f = ttk.Frame(parent)
        f.grid(row=row, column=1, sticky=tk.EW, pady=PAD_FORM)
        ttk.Button(f, text="编辑路由...",
                   command=lambda h=holder, cv=count_var, fm=form:
                       _open_routes_editor(parent, h, cv, fm)
                   ).pack(side=tk.LEFT)
        ttk.Label(f, textvariable=count_var, font=FONT_LABEL,
                  foreground="gray").pack(side=tk.LEFT, padx=6)
        form._widgets[field_name] = holder
        form._widgets[f"_{field_name}_label"] = count_var

    parent.columnconfigure(1, weight=1)


def _update_routes_label(holder: RoutesHolder, var: tk.StringVar):
    n = len(holder.routes)
    var.set(f"{n} 条路由" if n else "未配置")


def _open_routes_editor(parent: ttk.Frame, holder: RoutesHolder, count_var: tk.StringVar,
                        form: "ConfigForm | None" = None):
    RoutesEditor(parent.winfo_toplevel(), holder)
    _update_routes_label(holder, count_var)
    # Trigger preview refresh if available
    if form and hasattr(form, "_preview_cb") and form._preview_cb:
        parent.after(50, form._preview_cb)


# =====================================================================
# 报文预览
# =====================================================================

def _safe_get(widgets: dict, key: str, default=""):
    v = widgets.get(key)
    if v is None:
        return default
    try:
        return v.get()
    except Exception:
        return str(v) if v else default


def _build_raw_isis_packet(form: "ConfigForm") -> bytes | None:
    """根据当前表单参数构造一个 ISIS 报文（用于导出 pcap）。"""
    w = form._widgets
    attack = form._attack_name or ""
    try:
        from isis_attack.core.packet import build_iih_packet, build_lsp_with_tlvs
        from isis_attack.network.adapter import get_local_mac
        iface = _safe_get(w, "iface", "eth0")
        src_mac = get_local_mac(iface)
        sys_id = _safe_get(w, "sys_id", "1921.6800.1001")
        area = _safe_get(w, "area_addr", "49.0001")
        level = int(_safe_get(w, "level", "1"))
        auth_type = {"none": 0, "plain": 1, "md5": 2}.get(_safe_get(w, "auth_type", "none"), 0)
        auth_key = _safe_get(w, "auth_key", "").encode()

        if attack in ("iih-inject", "adjacency-break", "dis-hijack"):
            return build_iih_packet(
                sys_id=sys_id, area_addr=area, src_mac=src_mac, level=level,
                priority=int(_safe_get(w, "priority", "64")),
                hold_timer=int(_safe_get(w, "hold_timer", "30")),
                hello_interval=int(_safe_get(w, "hello_interval", "10")),
                auth_type=auth_type, auth_key=auth_key,
            )
        elif attack in ("route-inject", "max-seq", "purge-lsp", "fight-back", "overload-bit"):
            lsp_id = _safe_get(w, "lsp_id", "") or f"{sys_id}.00-00"
            seq = int(_safe_get(w, "sequence", "1"), 0)
            lifetime = int(_safe_get(w, "remaining_lifetime", "1200"))
            metric = int(_safe_get(w, "metric", "10"))
            net = _safe_get(w, "network_addr", "10.0.0.0")
            mask = _safe_get(w, "network_mask", "255.255.255.0")
            ol = bool(_safe_get(w, "overload_bit", False))
            return build_lsp_with_tlvs(
                sys_id=sys_id, lsp_id=lsp_id, src_mac=src_mac, level=level,
                sequence=seq, remaining_lifetime=lifetime,
                overload_bit=ol, metric=metric, network_addr=net,
                network_mask=mask, area_addr=area,
            )
    except Exception:
        import traceback; traceback.print_exc()
    return None


def _format_isis_preview(form: "ConfigForm") -> str:
    w = form._widgets
    attack = form._attack_name or ""

    iface = _safe_get(w, "iface", "eth0")
    target = _safe_get(w, "target", "01:80:C2:00:00:14")
    sys_id = _safe_get(w, "sys_id", "1921.6800.1001")
    area = _safe_get(w, "area_addr", "49.0001")
    level = _safe_get(w, "level", "1")

    src_mac = "??:??:??:??:??:??"
    try:
        from isis_attack.network.adapter import get_local_mac
        src_mac = get_local_mac(iface) or src_mac
    except Exception:
        pass

    l1 = "L1" if level == "1" else "L2"
    dst_map = {"1": "01:80:C2:00:00:14 (AllL1ISs)", "2": "01:80:C2:00:00:15 (AllL2ISs)"}
    dst_label = dst_map.get(level, "")

    lines = []
    lines.append("┌── L2 / LLC ──────────────────────────────────────┐")
    lines.append(f"│ Src MAC : {src_mac:<32} │")
    lines.append(f"│ Dst MAC : {dst_label:<32} │")
    lines.append(f"│ DSAP/SSAP: 0xFE/0xFE   Ctrl: 0x03               │")
    lines.append("├── ISIS Common Header ─────────────────────────────┤")
    lines.append(f"│ NLPID: 0x83   Hdr Len: 14   Version: 1          │")
    lines.append(f"│ System ID : {sys_id:<24} │")
    if attack in ("iih-inject", "adjacency-break", "dis-hijack"):
        pdu_name = "IIH"
    elif attack in ("route-inject", "max-seq", "purge-lsp", "fight-back", "overload-bit"):
        pdu_name = "LSP"
    elif attack in ("flood", "spf-recalc", "db-overflow"):
        pdu_name = "IIH/LSP"
    else:
        pdu_name = "?"
    lines.append(f"│ PDU Type : {l1} ({pdu_name})")

    # Attack-specific body
    if attack in ("iih-inject", "adjacency-break", "dis-hijack"):
        pri = _safe_get(w, "priority", "64")
        hold = _safe_get(w, "hold_timer", "30")
        hello = _safe_get(w, "hello_interval", "10")
        lines.append("├── IIH (IS-IS Hello) ──────────────────────────────┤")
        lines.append(f"│ Circuit Type: {l1}   Priority: {pri:<3}               │")
        lines.append(f"│ Hold Timer: {hold:<4}s   Hello Interval: {hello:<4}s     │")
        lines.append(f"│ LAN ID: {sys_id}.00                              │")
        lines.append("├── TLVs ──────────────────────────────────────────┤")
        lines.append(f"│ Area Addresses (1): {area}                       │")
        lines.append(f"│ Protocols Supported (129): IPv4 (0xCC)           │")
        auth = _safe_get(w, "auth_type", "none")
        if auth != "none":
            lines.append(f"│ Authentication ({'10' if auth=='plain' else '133'}): {auth}")

    elif attack in ("route-inject", "max-seq", "purge-lsp", "fight-back", "overload-bit"):
        lsp_id = _safe_get(w, "lsp_id", "") or f"{sys_id}.00-00"
        seq = _safe_get(w, "sequence", "1")
        lifetime = _safe_get(w, "remaining_lifetime", "1200")
        metric = _safe_get(w, "metric", "10")
        net = _safe_get(w, "network_addr", "10.0.0.0")
        mask = _safe_get(w, "network_mask", "255.255.255.0")
        ol = _safe_get(w, "overload_bit", False)
        lines.append("├── LSP ────────────────────────────────────────────┤")
        lines.append(f"│ LSP ID : {lsp_id:<32} │")
        lines.append(f"│ Sequence : {seq:<10}  Lifetime: {lifetime:<6}s      │")
        lines.append(f"│ Flags : {'OL ' if ol else ''}L1 IS                      │")
        lines.append("├── TLVs ──────────────────────────────────────────┤")
        lines.append(f"│ Area Addresses (1): {area}                       │")
        lines.append(f"│ Protocols Supported (129): IPv4 (0xCC)           │")
        lines.append(f"│ Hostname (137): {sys_id}                         │")
        # Single route (backward compatibility)
        if net != "0.0.0.0" and net != "":
            lines.append(f"│ IP Int. Reach (128): {net}/{mask} metric={metric}")
        # External routes from RoutesEditor
        routes_holder = w.get("external_routes")
        if routes_holder and hasattr(routes_holder, "routes"):
            routes = routes_holder.routes
            if routes:
                lines.append(f"│ 伪造路由条目 ({len(routes)} 条):")
                for i, r in enumerate(routes):
                    r_net = r.get("network", "-")
                    r_mask = r.get("mask", "255.255.255.0")
                    r_metric = r.get("metric", 10)
                    lines.append(f"│   #{i+1} {r_net}/{r_mask} metric={r_metric}")

    elif attack in ("flood", "spf-recalc", "db-overflow"):
        dur = _safe_get(w, "duration", "60")
        lines.append("├── DoS 攻击参数 ───────────────────────────────────┤")
        lines.append(f"│ Duration: {dur:<6}s   Rate: {_safe_get(w, 'packet_rate', '10')} pps")
        if attack == "spf-recalc":
            lines.append(f"│ LSP Change Interval: {_safe_get(w, 'lsp_change_interval', '2')}s")
        elif attack == "db-overflow":
            lines.append(f"│ LSP Count: {_safe_get(w, 'lsp_count', '1000')}")

    elif attack == "mitm":
        lines.append("├── MITM 参数 ──────────────────────────────────────┤")
        lines.append(f"│ Action: {_safe_get(w, 'action', 'modify')}")
        lines.append(f"│ Target A: {_safe_get(w, 'target_a', '')}")
        lines.append(f"│ Target B: {_safe_get(w, 'target_b', '')}")

    elif attack == "replay":
        lines.append("├── Replay 参数 ────────────────────────────────────┤")
        lines.append(f"│ PCAP: {_safe_get(w, 'capture_file', '')[:30]}")
        lines.append(f"│ Loop: {_safe_get(w, 'replay_loop', False)}   Interval: {_safe_get(w, 'replay_interval', '5')}s")

    lines.append("└──────────────────────────────────────────────────┘")
    return "\n".join(lines)


class PacketPreview(ttk.LabelFrame):
    """报文预览面板 — 显示构造的 IS-IS 报文结构。"""

    def __init__(self, parent, preview_fn, export_fn=None, **kw):
        super().__init__(parent, text="报文预览", padding=6, **kw)
        self._preview_fn = preview_fn
        self._export_fn = export_fn

        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, pady=(0, 4))
        if export_fn:
            ttk.Button(bar, text="导出 pcap", command=self._export).pack(side=tk.LEFT)
        ttk.Button(bar, text="刷新预览", command=self.refresh).pack(side=tk.RIGHT)

        self._text = tk.Text(self, font=("Consolas", 9), width=42, height=24,
                             bg="#1e1e1e", fg="#d4d4d4",
                             insertbackground="#ffffff",
                             relief=tk.FLAT, state=tk.DISABLED,
                             wrap=tk.NONE)
        self._text.pack(fill=tk.BOTH, expand=True)
        self.refresh()

    def _export(self):
        if self._export_fn:
            self._export_fn()

    def refresh(self):
        try:
            preview = self._preview_fn()
        except Exception:
            preview = "(报文预览不可用)"
        self._text.configure(state=tk.NORMAL)
        self._text.delete("1.0", tk.END)
        self._text.insert("1.0", preview)
        self._text.configure(state=tk.DISABLED)
