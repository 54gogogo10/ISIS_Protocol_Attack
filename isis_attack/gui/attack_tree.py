import tkinter as tk
from tkinter import ttk
from isis_attack.gui.styles import FONT_SM, ACCENT

ATTACK_TREE = {
    "adjacency (3)":  ["iih-inject", "adjacency-break", "dis-hijack"],
    "lsp (5)":        ["route-inject", "max-seq", "purge-lsp", "fight-back", "overload-bit"],
    "dos (3)":        ["flood", "spf-recalc", "db-overflow"],
    "protocol (2)":   ["mitm", "replay"],
}

DESCRIPTIONS = {
    "iih-inject":       "Inject forged IIH → unauthorized adjacency",
    "adjacency-break":  "Malformed IIH → break adjacency",
    "dis-hijack":       "Priority=127 IIH → hijack DIS",
    "route-inject":     "Poisoned LSP → route table corruption",
    "max-seq":          "Seq=0xFFFFFFFF → suppress legitimate LSP",
    "purge-lsp":        "Lifetime=0 → purge LSP from LSDB",
    "fight-back":       "Incrementing seq → LSP fight-back",
    "overload-bit":     "OL bit → exclude from SPF",
    "flood":            "Multi-thread IIH flood → CPU exhaustion",
    "spf-recalc":       "Changing LSP → force SPF recalculation",
    "db-overflow":      "Many LSPs → fill LSDB",
    "mitm":             "Intercept→modify→forward",
    "replay":           "PCAP replay → route flapping",
}

class AttackTreePanel(ttk.Frame):
    def __init__(self, parent, on_select=None):
        super().__init__(parent)
        self.on_select = on_select

        ttk.Label(self, text="Attack Tree", font=("Consolas", 10, "bold")).pack(
            anchor=tk.W, padx=4, pady=(4, 2))

        self.tree = ttk.Treeview(self, show="tree", selectmode="browse")
        self.tree.pack(fill=tk.BOTH, expand=True, padx=2)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self._populate()

        self._desc_label = ttk.Label(self, text="", font=FONT_SM,
                                     wraplength=250, justify=tk.LEFT)
        self._desc_label.pack(fill=tk.X, padx=4, pady=4)

    def _populate(self):
        for cat, attacks in ATTACK_TREE.items():
            cat_id = self.tree.insert("", "end", text=cat, open=True)
            for name in attacks:
                self.tree.insert(cat_id, "end", text=name, values=[name])

    def _on_select(self, event):
        sel = self.tree.selection()
        if sel:
            item = self.tree.item(sel[0])
            name = item["values"]
            if name:
                name = name[0]
                desc = DESCRIPTIONS.get(name, "")
                self._desc_label.configure(text=desc)
                if self.on_select:
                    self.on_select(name)
            else:
                self._desc_label.configure(text="")
