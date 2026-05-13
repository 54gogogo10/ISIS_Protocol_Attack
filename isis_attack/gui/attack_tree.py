import tkinter as tk
from tkinter import ttk

ATTACK_TREE = {
    "adjacency": ["iih-inject", "adjacency-break", "dis-hijack"],
    "lsp": ["route-inject", "max-seq", "purge-lsp", "fight-back", "overload-bit"],
    "dos": ["flood", "spf-recalc", "db-overflow"],
    "protocol": ["mitm", "replay"],
}

class AttackTreePanel(ttk.Frame):
    def __init__(self, parent, on_select=None):
        super().__init__(parent)
        self.on_select = on_select
        self.tree = ttk.Treeview(self, show="tree")
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self._populate()

    def _populate(self):
        for cat, attacks in ATTACK_TREE.items():
            cat_id = self.tree.insert("", "end", text=cat, open=True)
            for name in attacks:
                self.tree.insert(cat_id, "end", text=name, values=[name])

    def _on_select(self, event):
        sel = self.tree.selection()
        if sel and self.on_select:
            item = self.tree.item(sel[0])
            if item["values"]:
                self.on_select(item["values"][0])
