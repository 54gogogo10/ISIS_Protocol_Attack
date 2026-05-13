import tkinter as tk
from tkinter import ttk
import queue
from isis_attack.gui.styles import BG, FG

class LogPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.text = tk.Text(self, wrap=tk.WORD, bg=BG, fg=FG,
                            font=("Consolas", 9), state=tk.DISABLED,
                            insertbackground=FG, relief=tk.FLAT,
                            borderwidth=2, highlightthickness=0)
        scroll = ttk.Scrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._queue = queue.Queue()
        self._process_queue()

    def info(self, msg):
        self._queue.put(("info", msg))

    def error(self, msg):
        self._queue.put(("error", msg))

    def success(self, msg):
        self._queue.put(("success", msg))

    def _process_queue(self):
        while True:
            try:
                level, msg = self._queue.get_nowait()
                self._write(level, msg)
            except queue.Empty:
                break
        self.after(100, self._process_queue)

    def _write(self, level, msg):
        color = {"info": "#89b4fa", "error": "#f38ba8", "success": "#a6e3a1"}.get(level, FG)
        self.text.configure(state=tk.NORMAL)
        self.text.insert(tk.END, msg + "\n")
        self.text.see(tk.END)
        self.text.configure(state=tk.DISABLED)
