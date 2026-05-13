import tkinter as tk
from tkinter import ttk

class ConfigFormPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.entries = {}
        self._build_form()

    def _build_form(self):
        fields = [("iface", "Interface"), ("target", "Target"), ("sys_id", "System ID"),
                  ("area_addr", "Area Addr"), ("level", "Level")]
        for i, (key, label) in enumerate(fields):
            ttk.Label(self, text=label).grid(row=i, column=0, sticky="w", pady=2)
            entry = ttk.Entry(self, width=40)
            entry.grid(row=i, column=1, sticky="ew", pady=2, padx=5)
            self.entries[key] = entry
        self.columnconfigure(1, weight=1)

    def load_config(self, attack_name):
        for entry in self.entries.values():
            entry.delete(0, tk.END)
        self.entries["iface"].insert(0, "eth0")
        self.entries["target"].insert(0, "01:80:C2:00:00:14")
        self.entries["sys_id"].insert(0, "1921.6800.1001")
        self.entries["area_addr"].insert(0, "49.0001")
        self.entries["level"].insert(0, "1")
