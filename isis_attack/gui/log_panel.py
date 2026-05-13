import tkinter as tk
from tkinter import ttk
import queue

class LogPanel(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.text = tk.Text(self, wrap=tk.WORD, bg="#1e1e2e", fg="#cdd6f4",
                            font=("Consolas", 9), state=tk.DISABLED)
        scroll = ttk.Scrollbar(self, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set)
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._queue = queue.Queue()

    def info(self, msg):
        self._append(msg, "#89b4fa")

    def error(self, msg):
        self._append(msg, "#f38ba8")

    def _append(self, msg, color):
        self.text.configure(state=tk.NORMAL)
        self.text.insert(tk.END, msg + "\n")
        self.text.see(tk.END)
        self.text.configure(state=tk.DISABLED)
