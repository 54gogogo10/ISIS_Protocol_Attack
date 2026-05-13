import tkinter as tk
from tkinter import ttk
from isis_attack.gui.styles import FG, FONT, FONT_SM

FIELD_META = {
    "iface":       ("Interface", "eth0"),
    "target":      ("Target MAC", "01:80:C2:00:00:14"),
    "sys_id":      ("System ID", "1921.6800.1001"),
    "area_addr":   ("Area Addr", "49.0001"),
    "level":       ("Level (1/2)", "1"),
    "packet_rate": ("Packet Rate", "10"),
    "sniff_duration": ("Duration (s)", "30"),
}

ATTACK_EXTRA = {
    "iih-inject":       [("priority", "Priority", "127"), ("hold_timer", "Hold Timer", "30"),
                         ("hello_interval", "Hello Interval", "10")],
    "adjacency-break":  [],
    "dis-hijack":       [("priority", "Priority", "127"), ("hold_timer", "Hold Timer", "30")],
    "route-inject":     [("lsp_id", "LSP ID", ""), ("sequence", "Sequence", "1"),
                         ("metric", "Metric", "10"), ("network_addr", "Net Addr", "10.0.0.0"),
                         ("network_mask", "Net Mask", "255.255.255.0")],
    "max-seq":          [("lsp_id", "LSP ID", "")],
    "purge-lsp":        [("lsp_id", "LSP ID", "")],
    "fight-back":       [("lsp_id", "LSP ID", ""), ("metric", "Metric", "10"),
                         ("network_addr", "Net Addr", "10.0.0.0")],
    "overload-bit":     [("lsp_id", "LSP ID", "")],
    "flood":            [("thread_count", "Threads", "1"), ("duration", "Duration (s)", "60")],
    "spf-recalc":       [("duration", "Duration (s)", "30"), ("lsp_change_interval", "Change Intv", "2")],
    "db-overflow":      [("lsp_count", "LSP Count", "1000")],
    "mitm":             [("action", "Action", "modify")],
    "replay":           [("capture_file", "PCAP File", "")],
}

class ConfigFormPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.entries = {}
        self._build_form()

    def _build_form(self):
        canvas = tk.Canvas(self, bg="#1e1e2e", highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient=tk.VERTICAL, command=canvas.yview)
        self._form_frame = ttk.Frame(canvas)
        self._form_frame.bind("<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=self._form_frame, anchor=tk.NW, width=350)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        for ev in ("<Enter>",):
            canvas.bind(ev, lambda e: canvas.bind_all("<MouseWheel>",
                lambda e: canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")))
        canvas.bind("<Leave>", lambda e: canvas.unbind_all("<MouseWheel>"))

        self._base_frame = ttk.LabelFrame(self._form_frame, text="Common", padding=5)
        self._base_frame.pack(fill=tk.X, pady=(0, 5))
        self._extra_frame = ttk.LabelFrame(self._form_frame, text="Attack-Specific", padding=5)

        self._build_fields(self._base_frame, FIELD_META)
        self._extra_widgets = []

    def _build_fields(self, parent, fields):
        for i, (key, (label, default)) in enumerate(fields.items()):
            ttk.Label(parent, text=label, font=FONT_SM).grid(
                row=i, column=0, sticky="w", pady=1)
            entry = ttk.Entry(parent, width=35, font=FONT_SM)
            entry.grid(row=i, column=1, sticky="ew", pady=1, padx=(8, 0))
            entry.insert(0, default)
            self.entries[key] = entry
            parent.columnconfigure(1, weight=1)

    def load_config(self, attack_name):
        extras = ATTACK_EXTRA.get(attack_name, [])
        self._extra_frame.pack_forget()
        for w in self._extra_widgets:
            w.destroy()
        self._extra_widgets.clear()
        extra_keys = [k for k in self.entries if k not in FIELD_META]
        for k in extra_keys:
            del self.entries[k]
        for key, (label, default) in FIELD_META.items():
            if key in self.entries:
                self.entries[key].delete(0, tk.END)
                self.entries[key].insert(0, default)

        if extras:
            self._extra_frame.pack(fill=tk.X)
            for i, (key, label, default) in enumerate(extras):
                lbl = ttk.Label(self._extra_frame, text=label, font=FONT_SM)
                lbl.grid(row=i, column=0, sticky="w", pady=1)
                entry = ttk.Entry(self._extra_frame, width=35, font=FONT_SM)
                entry.grid(row=i, column=1, sticky="ew", pady=1, padx=(8, 0))
                entry.insert(0, default)
                self.entries[key] = entry
                self._extra_widgets.append(lbl)
                self._extra_widgets.append(entry)
            self._extra_frame.columnconfigure(1, weight=1)

    def get_values(self):
        return {key: entry.get().strip() for key, entry in self.entries.items()}
