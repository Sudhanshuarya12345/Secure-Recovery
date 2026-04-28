"""
pyrecovery.ui.panels.progress_panel — Progress display panel.

Shows:
    - Current action label
    - Progress bar (ttk.Progressbar)
    - Speed, ETA, file count labels
    - File type badges at the bottom

Thread safety:
    All methods MUST be called from the main Tkinter thread.
    The engine thread marshals updates via root.after().
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from typing import Optional


class ProgressPanel(ttk.Frame):
    """Reusable progress display widget for the Drive tab bottom."""

    def __init__(self, parent: tk.Widget, **kwargs):
        super().__init__(parent, **kwargs)
        self._build()

    def _build(self) -> None:
        # Title
        ttk.Label(self, text="Operation Progress",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=8, pady=(8, 4))

        # Container frame
        container = ttk.LabelFrame(self, text="")
        container.pack(fill="x", padx=8, pady=(0, 4))

        # Step label
        self._step_label = ttk.Label(container, text="Idle",
                                      font=("Segoe UI", 9))
        self._step_label.pack(anchor="w", padx=10, pady=(8, 2))

        # Progress bar
        self._progress_bar = ttk.Progressbar(container, orient="horizontal",
                                              length=600, mode="determinate",
                                              maximum=100)
        self._progress_bar.pack(fill="x", padx=10, pady=2)

        # Stats row
        stats_frame = ttk.Frame(container)
        stats_frame.pack(fill="x", padx=10, pady=(2, 4))

        self._percent_label = ttk.Label(stats_frame, text="0%",
                                         font=("Segoe UI", 9))
        self._percent_label.pack(side="left")

        self._scanned_label = ttk.Label(stats_frame, text="",
                                         font=("Segoe UI", 9))
        self._scanned_label.pack(side="left", padx=(16, 0))

        self._speed_label = ttk.Label(stats_frame, text="Speed: —",
                                       font=("Segoe UI", 9))
        self._speed_label.pack(side="left", padx=(16, 0))

        self._eta_label = ttk.Label(stats_frame, text="ETA: —",
                                     font=("Segoe UI", 9))
        self._eta_label.pack(side="left", padx=(16, 0))

        self._files_label = ttk.Label(stats_frame, text="Files: 0",
                                       font=("Segoe UI", 9, "bold"))
        self._files_label.pack(side="right")

        # File type badges frame
        self._badge_frame = ttk.Frame(self)
        self._badge_frame.pack(fill="x", padx=8, pady=(0, 8))

        self._badges: dict[str, ttk.Label] = {}

    def update_progress(
        self,
        percent: float = 0.0,
        current_action: str = "",
        speed_bps: float = 0.0,
        eta_seconds: float = 0.0,
        bytes_scanned: int = 0,
        total_bytes: int = 0,
        files_by_type: dict[str, int] | None = None,
        total_files: int = 0,
    ) -> None:
        """Update all progress indicators.  MUST be called from main thread."""
        self._progress_bar["value"] = percent
        self._percent_label.config(text=f"{percent:.0f}%")

        if current_action:
            self._step_label.config(text=f"Step: {current_action}")

        # Format scanned/total
        if total_bytes > 0:
            scanned_mb = bytes_scanned / (1024 * 1024)
            total_mb = total_bytes / (1024 * 1024)
            if total_mb >= 1024:
                self._scanned_label.config(
                    text=f"{scanned_mb / 1024:.1f} GB / {total_mb / 1024:.1f} GB"
                )
            else:
                self._scanned_label.config(
                    text=f"{scanned_mb:.0f} MB / {total_mb:.0f} MB"
                )

        # Speed
        if speed_bps > 0:
            speed_mb = speed_bps / (1024 * 1024)
            self._speed_label.config(text=f"Speed: {speed_mb:.1f} MB/s")
        else:
            self._speed_label.config(text="Speed: —")

        # ETA
        if eta_seconds > 0:
            mins, secs = divmod(int(eta_seconds), 60)
            self._eta_label.config(text=f"ETA: {mins}m {secs:02d}s")
        else:
            self._eta_label.config(text="ETA: —")

        # Files count
        self._files_label.config(text=f"Files: {total_files}")

        # Badges
        if files_by_type:
            self._update_badges(files_by_type)

    def _update_badges(self, files_by_type: dict[str, int]) -> None:
        """Update file type badges.  Only show types with count > 0."""
        colors = {
            "jpg": "#2196F3", "jpeg": "#2196F3", "png": "#4CAF50",
            "gif": "#FF9800", "bmp": "#9C27B0", "pdf": "#F44336",
            "docx": "#3F51B5", "zip": "#795548", "mp4": "#E91E63",
            "mp3": "#00BCD4", "wav": "#009688", "avi": "#FF5722",
        }

        for ext, count in sorted(files_by_type.items()):
            if ext not in self._badges:
                color = colors.get(ext, "#607D8B")
                badge = ttk.Label(self._badge_frame,
                                   text=f" {ext}: {count} ",
                                   font=("Segoe UI", 8, "bold"),
                                   background=color, foreground="white",
                                   padding=(4, 2))
                badge.pack(side="left", padx=2)
                self._badges[ext] = badge
            else:
                self._badges[ext].config(text=f" {ext}: {count} ")

    def reset(self) -> None:
        """Reset all progress indicators to initial state."""
        self._progress_bar["value"] = 0
        self._percent_label.config(text="0%")
        self._step_label.config(text="Idle")
        self._speed_label.config(text="Speed: —")
        self._eta_label.config(text="ETA: —")
        self._scanned_label.config(text="")
        self._files_label.config(text="Files: 0")

        for badge in self._badges.values():
            badge.destroy()
        self._badges.clear()

    def set_complete(self, total_files: int, duration: float) -> None:
        """Mark progress as complete."""
        self._progress_bar["value"] = 100
        self._percent_label.config(text="100%")
        self._step_label.config(
            text=f"✓ Complete — {total_files} files recovered in {duration:.0f}s"
        )
        self._speed_label.config(text="")
        self._eta_label.config(text="")
