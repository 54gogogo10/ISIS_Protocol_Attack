"""动态配置表单 — 根据攻击类型动态生成参数字段。"""

import tkinter as tk
from tkinter import ttk
from typing import Any
from .styles import FONT_LABEL, FONT_ENTRY, PAD_FORM, PAD_OUTER, SECTION_GAP


def get_network_interfaces() -> list[str]:
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
    "level":          {"widget": "combo",   "label": "IS-IS 级别", "choices": ["1", "2"], "default": "1"},
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
    "sequence":          {"widget": "entry",   "label": "序列号 (hex)", "default": "1"},
    "remaining_lifetime":{"widget": "spinbox", "label": "Remaining Lifetime(s)", "from_": 0, "to": 65535, "default": 1200},
    "metric":            {"widget": "spinbox", "label": "Metric", "from_": 0, "to": 16777215, "default": 10},
    "network_addr":      {"widget": "entry",   "label": "网络地址", "default": "10.0.0.0"},
    "network_mask":      {"widget": "entry",   "label": "网络掩码", "default": "255.255.255.0"},

    # -- DoS 专属 --
    "duration":            {"widget": "spinbox", "label": "持续时间(秒)", "from_": 1, "to": 86400, "default": 60},
    "thread_count":        {"widget": "spinbox", "label": "并发线程数", "from_": 1, "to": 100, "default": 1},
    "lsp_change_interval": {"widget": "spinbox", "label": "LSP 变化间隔(秒)", "from_": 1, "to": 3600, "default": 2},
    "lsp_count":           {"widget": "spinbox", "label": "注入 LSP 数量", "from_": 1, "to": 100000, "default": 1000},

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
    "iih-inject":       ["hello_interval", "hold_timer", "priority", "auth_type", "auth_key"],
    "adjacency-break":  ["hold_timer", "priority"],
    "dis-hijack":       ["hello_interval", "hold_timer", "priority"],
    "route-inject":     ["lsp_id", "sequence", "remaining_lifetime", "metric",
                         "network_addr", "network_mask", "auth_type", "auth_key"],
    "max-seq":          ["lsp_id"],
    "purge-lsp":        ["lsp_id", "sequence"],
    "fight-back":       ["lsp_id", "sequence", "metric", "network_addr", "network_mask"],
    "overload-bit":     ["lsp_id", "sequence", "remaining_lifetime"],
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

    parent.columnconfigure(1, weight=1)
