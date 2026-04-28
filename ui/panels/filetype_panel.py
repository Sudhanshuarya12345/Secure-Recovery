"""
pyrecovery.ui.panels.filetype_panel — File type selection panel.

Category checkboxes with individual type checkboxes.
Select All / None buttons.
Recovery strategy radio buttons.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional


# File type definitions by category
FILE_CATEGORIES = {
    "Images": {
        "icon": "📷",
        "types": [
            ("JPEG (.jpg)", "jpg", True),
            ("PNG (.png)", "png", True),
            ("GIF (.gif)", "gif", True),
            ("BMP (.bmp)", "bmp", True),
            ("TIFF (.tiff)", "tiff", False),
            ("WebP (.webp)", "webp", False),
        ],
    },
    "Documents": {
        "icon": "📄",
        "types": [
            ("PDF (.pdf)", "pdf", True),
            ("DOCX (.docx)", "docx", True),
            ("XLSX (.xlsx)", "xlsx", False),
            ("PPTX (.pptx)", "pptx", False),
            ("RTF (.rtf)", "rtf", False),
        ],
    },
    "Videos": {
        "icon": "🎬",
        "types": [
            ("MP4 (.mp4)", "mp4", False),
            ("AVI (.avi)", "avi", False),
            ("MKV (.mkv)", "mkv", False),
        ],
    },
    "Audio": {
        "icon": "🎵",
        "types": [
            ("MP3 (.mp3)", "mp3", False),
            ("WAV (.wav)", "wav", False),
            ("FLAC (.flac)", "flac", False),
            ("OGG (.ogg)", "ogg", False),
        ],
    },
    "Archives": {
        "icon": "📦",
        "types": [
            ("ZIP (.zip)", "zip", False),
            ("RAR (.rar)", "rar", False),
            ("7Z (.7z)", "7z", False),
        ],
    },
    "System": {
        "icon": "⚙",
        "types": [
            ("EXE (.exe)", "exe", False),
            ("ELF", "elf", False),
            ("SQLite (.sqlite)", "sqlite", False),
        ],
    },
}


class FileTypePanel(ttk.Frame):
    """File type selection with categories and recovery strategy."""

    def __init__(self, parent: tk.Widget, **kwargs):
        super().__init__(parent, **kwargs)
        self._type_vars: dict[str, tk.BooleanVar] = {}
        self._category_vars: dict[str, tk.BooleanVar] = {}
        self._strategy_var = tk.StringVar(value="both")
        self._build()

    def _build(self) -> None:
        # ── Top buttons ─────────────────────────────────────────────
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=8, pady=(8, 4))

        ttk.Label(btn_frame, text="Select file types to recover:",
                  font=("Segoe UI", 10, "bold")).pack(side="left")

        ttk.Button(btn_frame, text="Select All",
                    command=self._select_all).pack(side="right", padx=(4, 0))
        ttk.Button(btn_frame, text="None",
                    command=self._select_none).pack(side="right")

        # ── Scrollable categories area ──────────────────────────────
        canvas = tk.Canvas(self, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)

        scroll_frame.bind("<Configure>",
                           lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=4)
        scrollbar.pack(side="right", fill="y", padx=(0, 8), pady=4)

        # Enable mouse wheel scrolling
        def _on_mousewheel(event):
            canvas.yview_scroll(-1 * (event.delta // 120), "units")
        canvas.bind_all("<MouseWheel>", _on_mousewheel, add="+")

        for cat_name, cat_info in FILE_CATEGORIES.items():
            self._build_category(scroll_frame, cat_name, cat_info)

        # ── Recovery strategy ───────────────────────────────────────
        sep = ttk.Separator(self, orient="horizontal")
        sep.pack(fill="x", padx=8, pady=8)

        strat_frame = ttk.LabelFrame(self, text="Recovery Strategy", padding=8)
        strat_frame.pack(fill="x", padx=8, pady=(0, 8))

        ttk.Radiobutton(strat_frame,
                         text="Filesystem-aware + Carving (Recommended)",
                         variable=self._strategy_var, value="both"
                         ).pack(anchor="w", pady=2)
        ttk.Radiobutton(strat_frame,
                         text="Filesystem-aware only (Faster)",
                         variable=self._strategy_var, value="filesystem"
                         ).pack(anchor="w", pady=2)
        ttk.Radiobutton(strat_frame,
                         text="Raw carving only (Deepest scan)",
                         variable=self._strategy_var, value="carving"
                         ).pack(anchor="w", pady=2)

    def _build_category(self, parent: ttk.Frame, name: str, info: dict) -> None:
        """Build a category section with header checkbox and individual types."""
        frame = ttk.Frame(parent)
        frame.pack(fill="x", padx=4, pady=4)

        # Category header
        cat_var = tk.BooleanVar(value=name in ("Images", "Documents"))
        self._category_vars[name] = cat_var

        header = ttk.Frame(frame)
        header.pack(fill="x")

        icon = info.get("icon", "")
        ttk.Label(header, text=f"{icon} {name}",
                  font=("Segoe UI", 10, "bold")).pack(side="left")

        cat_cb = ttk.Checkbutton(
            header, text="Select category",
            variable=cat_var,
            command=lambda n=name: self._toggle_category(n),
        )
        cat_cb.pack(side="right")

        # Individual types
        types_frame = ttk.Frame(frame)
        types_frame.pack(fill="x", padx=20, pady=(2, 0))

        row_frame = None
        for i, (display, ext, default_on) in enumerate(info["types"]):
            if i % 3 == 0:
                row_frame = ttk.Frame(types_frame)
                row_frame.pack(fill="x", pady=1)

            var = tk.BooleanVar(value=default_on)
            self._type_vars[ext] = var
            cb = ttk.Checkbutton(row_frame, text=display, variable=var)
            cb.pack(side="left", padx=(0, 16))

    def _toggle_category(self, category: str) -> None:
        """Toggle all types in a category on/off."""
        cat_var = self._category_vars[category]
        state = cat_var.get()
        for _, ext, _ in FILE_CATEGORIES[category]["types"]:
            if ext in self._type_vars:
                self._type_vars[ext].set(state)

    def _select_all(self) -> None:
        """Check all file types."""
        for var in self._type_vars.values():
            var.set(True)
        for var in self._category_vars.values():
            var.set(True)

    def _select_none(self) -> None:
        """Uncheck all file types."""
        for var in self._type_vars.values():
            var.set(False)
        for var in self._category_vars.values():
            var.set(False)

    def get_selected_types(self) -> list[str]:
        """Return list of selected file type extensions."""
        selected = [ext for ext, var in self._type_vars.items() if var.get()]
        return selected if selected else ["all"]

    def get_selected_categories(self) -> list[str]:
        """Return list of selected category names (for engine config)."""
        # Map extensions to categories
        cat_map = {}
        for cat_name, info in FILE_CATEGORIES.items():
            for _, ext, _ in info["types"]:
                cat_map[ext] = cat_name.lower()

        selected_types = self.get_selected_types()
        if "all" in selected_types:
            return ["all"]

        categories = set()
        for ext in selected_types:
            if ext in cat_map:
                categories.add(cat_map[ext])
        return list(categories) if categories else ["all"]

    def get_strategy(self) -> str:
        """Return selected recovery strategy."""
        return self._strategy_var.get()
