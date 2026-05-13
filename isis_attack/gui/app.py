import tkinter as tk
from tkinter import ttk
from isis_attack.gui.styles import BG, FG
from isis_attack.gui.attack_tree import AttackTreePanel
from isis_attack.gui.config_form import ConfigFormPanel
from isis_attack.gui.log_panel import LogPanel

class ISISAttackApp:
    def __init__(self, root):
        self.root = root
        root.title("ISIS Protocol Attack Simulator")
        root.geometry("1100x720")
        root.configure(bg=BG)
        root.resizable(True, True)

        left = ttk.Frame(root, width=280)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=5, pady=5)

        self.tree = AttackTreePanel(left, on_select=self._on_attack_select)
        self.tree.pack(fill=tk.BOTH, expand=True)

        right = ttk.Frame(root)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.form = ConfigFormPanel(right)
        self.form.pack(fill=tk.BOTH, expand=True)

        bottom = ttk.Frame(root, height=180)
        bottom.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=5)

        self.log = LogPanel(bottom)
        self.log.pack(fill=tk.BOTH, expand=True)

    def _on_attack_select(self, attack_name):
        self.form.load_config(attack_name)
        self.log.info(f"Selected: {attack_name}")
