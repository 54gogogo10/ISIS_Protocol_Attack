"""日志面板 — 彩色日志输出，支持队列缓冲。"""

import tkinter as tk
from tkinter import ttk
from .styles import BG_LOG, LOG_TAGS, FONT_LOG


class LogPanel(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG_LOG, **kw)

        self._text = tk.Text(self, wrap=tk.WORD, bg=BG_LOG, fg="#d4d4d4",
                             font=FONT_LOG, state=tk.DISABLED,
                             insertbackground="#ffffff",
                             relief=tk.FLAT, borderwidth=2, highlightthickness=0)
        scroll = ttk.Scrollbar(self, command=self._text.yview)
        self._text.configure(yscrollcommand=scroll.set)
        self._text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def write(self, level: str, message: str):
        """写入一条日志 — 线程安全。"""
        color = LOG_TAGS.get(level, LOG_TAGS["INFO"])
        self._text.after(0, self._append, level, message, color)

    def _append(self, level, message, color):
        try:
            self._text.configure(state=tk.NORMAL)
            self._text.insert(tk.END, f"[{level}] {message}\n", (level,))
            self._text.tag_configure(level, foreground=color)
            self._text.see(tk.END)
            self._text.configure(state=tk.DISABLED)
        except Exception:
            pass
