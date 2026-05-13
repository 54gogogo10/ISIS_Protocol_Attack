import tkinter as tk
from tkinter import ttk
from isis_attack.gui.styles import BG, FG, FONT, FONT_SM
from isis_attack.gui.attack_tree import AttackTreePanel
from isis_attack.gui.config_form import ConfigFormPanel
from isis_attack.gui.log_panel import LogPanel
from isis_attack.cli.commands import ATTACK_REGISTRY


class ISISAttackApp:
    def __init__(self, root):
        self.root = root
        root.title("ISIS Protocol Attack Simulator")
        root.geometry("1100x720")
        root.configure(bg=BG)
        root.minsize(800, 500)

        self._attack_thread = None
        self._selected_attack = None

        self._build_toolbar()
        self._build_body()
        self._build_log()

    # ------------------------------------------------------------------
    # Toolbar
    # ------------------------------------------------------------------

    def _build_toolbar(self):
        bar = ttk.Frame(self.root)
        bar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=(5, 0))

        self._attack_label = ttk.Label(bar, text="Select an attack from the tree →", font=FONT)
        self._attack_label.pack(side=tk.LEFT, padx=5)

        self._stop_btn = ttk.Button(bar, text="■ Stop", command=self._on_stop, state=tk.DISABLED)
        self._stop_btn.pack(side=tk.RIGHT, padx=3)

        self._run_btn = ttk.Button(bar, text="▶ Run", command=self._on_run, state=tk.DISABLED)
        self._run_btn.pack(side=tk.RIGHT, padx=3)

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=5, pady=2)

    # ------------------------------------------------------------------
    # Body: left tree + right form
    # ------------------------------------------------------------------

    def _build_body(self):
        body = ttk.Frame(self.root)
        body.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=(0, 3))

        # Left panel — attack tree (fixed width)
        left = ttk.Frame(body, width=280)
        left.pack(side=tk.LEFT, fill=tk.Y)
        left.pack_propagate(False)

        self.tree = AttackTreePanel(left, on_select=self._on_attack_select)
        self.tree.pack(fill=tk.BOTH, expand=True)

        # Separator
        ttk.Separator(body, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=2)

        # Right panel — config form (expands)
        right = ttk.Frame(body)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.form = ConfigFormPanel(right)
        self.form.pack(fill=tk.BOTH, expand=True)

    # ------------------------------------------------------------------
    # Log panel (bottom)
    # ------------------------------------------------------------------

    def _build_log(self):
        bottom = ttk.Frame(self.root, height=200)
        bottom.pack(side=tk.BOTTOM, fill=tk.X, padx=5, pady=(0, 5))
        bottom.pack_propagate(False)

        ttk.Separator(bottom, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=(0, 2))

        self.log = LogPanel(bottom)
        self.log.pack(fill=tk.BOTH, expand=True)

    # ------------------------------------------------------------------
    # Callbacks
    # ------------------------------------------------------------------

    def _on_attack_select(self, attack_name):
        self._selected_attack = attack_name
        self._attack_label.configure(text=f"Attack: {attack_name}")
        self.form.load_config(attack_name)
        self._run_btn.configure(state=tk.NORMAL)
        self.log.info(f"Selected: {attack_name}")

    def _on_run(self):
        if not self._selected_attack:
            return
        self._run_btn.configure(state=tk.DISABLED)
        self._stop_btn.configure(state=tk.NORMAL)

        kwargs = self.form.get_values()
        attack_name = self._selected_attack
        self.log.info(f"Starting {attack_name}...")

        import threading
        from isis_attack.config.config import build_config

        attack_cls, config_cls = ATTACK_REGISTRY[attack_name]

        def _run():
            try:
                config = build_config(attack_name, kwargs)
                attack = attack_cls(config)
                result = attack.run()
                self.root.after(0, self._on_done, result)
            except Exception as e:
                self.root.after(0, self._on_error, str(e))

        self._attack_thread = threading.Thread(target=_run, daemon=True)
        self._attack_thread.start()

    def _on_stop(self):
        self.log.info("Stop requested")
        self._run_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)

    def _on_done(self, result):
        self._run_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)
        if result.success:
            self.log.success(f"Done: {result.details} (packets: {result.packets_sent})")
        else:
            self.log.error(f"Failed: {result.details}")

    def _on_error(self, msg):
        self._run_btn.configure(state=tk.NORMAL)
        self._stop_btn.configure(state=tk.DISABLED)
        self.log.error(f"Error: {msg}")
