"""
pyrecovery.ui.app — Main Tkinter application window.

Launch with: ``python main.py --ui``

Layout:
    - Title bar: "PyRecovery v1.0 — File Recovery Tool"
    - Notebook with 4 tabs: Drive Selection, File Types, Settings, Log
    - Thread-safe: all background work uses root.after() for widget updates

Technology: Tkinter + ttk (built-in Python — no extra install).
Light/neutral system colors — no dark theme.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class PyRecoveryApp(tk.Tk):
    """Main application window for PyRecovery GUI."""

    def __init__(self):
        super().__init__()

        # ── Window setup ────────────────────────────────────────────
        self.title("PyRecovery v1.0 — File Recovery Tool")
        self.geometry("920x720")
        self.minsize(800, 600)
        self.resizable(True, True)

        # Store reference to root for thread-safe callbacks
        self.root = self

        # ── Style ───────────────────────────────────────────────────
        self._setup_style()

        # ── Header ──────────────────────────────────────────────────
        header = ttk.Frame(self, padding=(12, 8))
        header.pack(fill="x")

        ttk.Label(header, text="🔍 PyRecovery v1.0",
                  font=("Segoe UI", 14, "bold")).pack(side="left")
        ttk.Label(header, text="File Recovery Tool",
                  font=("Segoe UI", 10),
                  foreground="#666").pack(side="left", padx=(8, 0))
        ttk.Label(header, text="🔒 Source is never modified",
                  font=("Segoe UI", 8),
                  foreground="#888").pack(side="right")

        ttk.Separator(self, orient="horizontal").pack(fill="x")

        # ── Notebook (tabs) ─────────────────────────────────────────
        self._notebook = ttk.Notebook(self)
        self._notebook.pack(fill="both", expand=True, padx=4, pady=4)

        # Import panels
        from ui.panels.drive_panel import DrivePanel
        from ui.panels.filetype_panel import FileTypePanel
        from ui.panels.settings_panel import SettingsPanel
        from ui.panels.log_panel import LogPanel

        # Create panels — order matters (drive_panel needs filetype and settings refs)
        self.filetype_panel = FileTypePanel(self._notebook)
        self.settings_panel = SettingsPanel(self._notebook)
        self.log_panel = LogPanel(self._notebook)
        self.drive_panel = DrivePanel(self._notebook, app=self)

        # Add tabs
        self._notebook.add(self.drive_panel, text="  Drive Selection  ")
        self._notebook.add(self.filetype_panel, text="  File Types  ")
        self._notebook.add(self.settings_panel, text="  Settings  ")
        self._notebook.add(self.log_panel, text="  Log  ")

        # ── Status bar ──────────────────────────────────────────────
        status_frame = ttk.Frame(self, padding=(8, 4))
        status_frame.pack(fill="x", side="bottom")

        ttk.Separator(self, orient="horizontal").pack(fill="x", side="bottom")

        self._status_label = ttk.Label(status_frame,
                                        text="Ready — Select a drive or image file to begin",
                                        font=("Segoe UI", 8), foreground="#888")
        self._status_label.pack(side="left")

        ttk.Label(status_frame, text="PyRecovery © 2026",
                  font=("Segoe UI", 8), foreground="#AAA").pack(side="right")

        # ── Auto-refresh drives on startup ──────────────────────────
        self.after(500, self.drive_panel._refresh_drives)

        # Log startup
        self.log_panel.add_entry("INFO", "PyRecovery GUI started")

    def _setup_style(self) -> None:
        """Configure ttk styles for a clean, professional look."""
        style = ttk.Style(self)

        # Use clam theme on all platforms for consistency
        available = style.theme_names()
        if "vista" in available:
            style.theme_use("vista")
        elif "clam" in available:
            style.theme_use("clam")

        # Custom styles
        style.configure("TNotebook", padding=2)
        style.configure("TNotebook.Tab", padding=(12, 6),
                         font=("Segoe UI", 9))

        style.configure("TButton", padding=(8, 4),
                         font=("Segoe UI", 9))

        style.configure("TLabel", font=("Segoe UI", 9))

        style.configure("Treeview", font=("Segoe UI", 9), rowheight=24)
        style.configure("Treeview.Heading",
                         font=("Segoe UI", 9, "bold"))

    def set_status(self, text: str) -> None:
        """Update status bar text (thread-safe if called via root.after)."""
        self._status_label.config(text=text)
