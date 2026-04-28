"""
pyrecovery.ui.panels.log_panel — Scrollable log panel with color-coded entries.

Color coding:
    INFO  = black (default)
    FOUND = green
    WARN  = orange
    ERROR = red
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk, filedialog
from datetime import datetime


class LogPanel(ttk.Frame):
    """Scrollable log viewer with color-coded entries."""

    def __init__(self, parent: tk.Widget, **kwargs):
        super().__init__(parent, **kwargs)
        self._build()

    def _build(self) -> None:
        # Button bar
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=8, pady=(8, 4))

        ttk.Button(btn_frame, text="Clear",
                    command=self._clear).pack(side="left", padx=(0, 4))
        ttk.Button(btn_frame, text="Save Log...",
                    command=self._save_log).pack(side="left")

        self._entry_count_label = ttk.Label(btn_frame, text="0 entries",
                                             font=("Segoe UI", 9))
        self._entry_count_label.pack(side="right", padx=8)

        # Text widget with scrollbar
        text_frame = ttk.Frame(self)
        text_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        self._text = tk.Text(text_frame, wrap="word", state="disabled",
                              font=("Consolas", 9), bg="#FAFAFA",
                              relief="sunken", borderwidth=1)
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical",
                                   command=self._text.yview)
        self._text.configure(yscrollcommand=scrollbar.set)

        self._text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Configure tags for color coding
        self._text.tag_configure("INFO", foreground="#333333")
        self._text.tag_configure("FOUND", foreground="#2E7D32")
        self._text.tag_configure("WARN", foreground="#E65100")
        self._text.tag_configure("ERROR", foreground="#C62828")
        self._text.tag_configure("timestamp", foreground="#9E9E9E")

        self._count = 0

    def add_entry(self, level: str, message: str) -> None:
        """Add a log entry.  MUST be called from main thread."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tag = level.upper() if level.upper() in ("INFO", "FOUND", "WARN", "ERROR") else "INFO"

        self._text.configure(state="normal")
        self._text.insert("end", f"[{timestamp}] ", "timestamp")
        self._text.insert("end", f"{tag:5s} ", tag)
        self._text.insert("end", f"{message}\n", tag)
        self._text.see("end")
        self._text.configure(state="disabled")

        self._count += 1
        self._entry_count_label.config(text=f"{self._count} entries")

    def _clear(self) -> None:
        """Clear all log entries."""
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.configure(state="disabled")
        self._count = 0
        self._entry_count_label.config(text="0 entries")

    def _save_log(self) -> None:
        """Save log contents to a file."""
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            title="Save Log File",
        )
        if path:
            content = self._text.get("1.0", "end")
            with open(path, "w", encoding="utf-8") as f:
                f.write(content)
