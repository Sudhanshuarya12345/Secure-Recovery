"""
pyrecovery.ui.panels.settings_panel — Settings tab panel.

Scan settings, output settings, forensics settings, and safety controls.
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class SettingsPanel(ttk.Frame):
    """Settings panel with scan, output, forensics, and safety sections."""

    def __init__(self, parent: tk.Widget, **kwargs):
        super().__init__(parent, **kwargs)
        self._build()

    def _build(self) -> None:
        # ── Scan Settings ───────────────────────────────────────────
        scan_frame = ttk.LabelFrame(self, text="Scan Settings", padding=8)
        scan_frame.pack(fill="x", padx=8, pady=(8, 4))

        # Chunk size
        row1 = ttk.Frame(scan_frame)
        row1.pack(fill="x", pady=2)
        ttk.Label(row1, text="Chunk size:").pack(side="left")
        self._chunk_size_var = tk.StringVar(value="1 MB")
        chunk_combo = ttk.Combobox(row1, textvariable=self._chunk_size_var,
                                    values=["512 KB", "1 MB", "2 MB", "4 MB"],
                                    state="readonly", width=10)
        chunk_combo.pack(side="left", padx=(8, 4))
        ttk.Label(row1, text="(larger = faster, more RAM)",
                  font=("Segoe UI", 8), foreground="#888").pack(side="left")

        # Max file size
        row2 = ttk.Frame(scan_frame)
        row2.pack(fill="x", pady=2)
        ttk.Label(row2, text="Max file size:").pack(side="left")
        self._max_size_var = tk.StringVar(value="500 MB")
        max_combo = ttk.Combobox(row2, textvariable=self._max_size_var,
                                  values=["100 MB", "250 MB", "500 MB", "1 GB", "2 GB"],
                                  state="readonly", width=10)
        max_combo.pack(side="left", padx=(8, 4))
        ttk.Label(row2, text="(cap per recovered file)",
                  font=("Segoe UI", 8), foreground="#888").pack(side="left")

        # Skip duplicates
        self._dedup_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(scan_frame, text="Skip duplicates (MD5 hash deduplication)",
                         variable=self._dedup_var).pack(anchor="w", pady=2)

        # Save partial files
        self._partials_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(scan_frame, text="Save partial files (files with no footer found)",
                         variable=self._partials_var).pack(anchor="w", pady=2)

        # ── Output Settings ─────────────────────────────────────────
        output_frame = ttk.LabelFrame(self, text="Output Settings", padding=8)
        output_frame.pack(fill="x", padx=8, pady=4)

        # Folder structure
        ttk.Label(output_frame, text="Folder structure:").pack(anchor="w")
        self._folder_var = tk.StringVar(value="by_type")
        ttk.Radiobutton(output_frame, text="By type (jpg/, pdf/, mp4/)",
                         variable=self._folder_var, value="by_type"
                         ).pack(anchor="w", padx=20, pady=1)
        ttk.Radiobutton(output_frame, text="By batch (recup_dir.1/, recup_dir.2/)",
                         variable=self._folder_var, value="by_batch"
                         ).pack(anchor="w", padx=20, pady=1)
        ttk.Radiobutton(output_frame, text="Flat (all files in one folder)",
                         variable=self._folder_var, value="flat"
                         ).pack(anchor="w", padx=20, pady=1)

        # File naming
        ttk.Label(output_frame, text="File naming:").pack(anchor="w", pady=(8, 0))
        self._naming_var = tk.StringVar(value="offset")
        ttk.Radiobutton(output_frame, text="f{offset}.{ext}  (e.g. f000016842752.jpg)",
                         variable=self._naming_var, value="offset"
                         ).pack(anchor="w", padx=20, pady=1)
        ttk.Radiobutton(output_frame, text="f{counter}.{ext}  (e.g. f00001.jpg)",
                         variable=self._naming_var, value="counter"
                         ).pack(anchor="w", padx=20, pady=1)

        # ── Forensics Settings ──────────────────────────────────────
        forensics_frame = ttk.LabelFrame(self, text="Forensics Settings", padding=8)
        forensics_frame.pack(fill="x", padx=8, pady=4)

        self._hash_report_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(forensics_frame, text="Generate hash report (SHA256 + MD5 manifest)",
                         variable=self._hash_report_var).pack(anchor="w", pady=2)

        self._timeline_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(forensics_frame, text="Generate timeline (timestamp analysis)",
                         variable=self._timeline_var).pack(anchor="w", pady=2)

        self._forensic_log_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(forensics_frame, text="Forensic log (immutable chain of custody)",
                         variable=self._forensic_log_var).pack(anchor="w", pady=2)

        # ── Safety ──────────────────────────────────────────────────
        safety_frame = ttk.LabelFrame(self, text="Safety", padding=8)
        safety_frame.pack(fill="x", padx=8, pady=(4, 8))

        self._readonly_var = tk.BooleanVar(value=True)
        ro_cb = ttk.Checkbutton(safety_frame, text="Read-only mode (cannot be unchecked)",
                                 variable=self._readonly_var, state="disabled")
        ro_cb.pack(anchor="w", pady=2)

        self._verify_output_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(safety_frame, text="Verify output device (prevent writing to source)",
                         variable=self._verify_output_var).pack(anchor="w", pady=2)

    # ── Getters ─────────────────────────────────────────────────────

    def get_chunk_size(self) -> int:
        """Return chunk size in bytes."""
        text = self._chunk_size_var.get()
        sizes = {"512 KB": 512*1024, "1 MB": 1024*1024,
                 "2 MB": 2*1024*1024, "4 MB": 4*1024*1024}
        return sizes.get(text, 1024*1024)

    def get_max_file_size(self) -> int:
        """Return max file size in bytes."""
        text = self._max_size_var.get()
        sizes = {"100 MB": 100*1024*1024, "250 MB": 250*1024*1024,
                 "500 MB": 500*1024*1024, "1 GB": 1024*1024*1024,
                 "2 GB": 2*1024*1024*1024}
        return sizes.get(text, 500*1024*1024)

    def get_skip_duplicates(self) -> bool:
        return self._dedup_var.get()

    def get_save_partials(self) -> bool:
        return self._partials_var.get()

    def get_folder_structure(self) -> str:
        return self._folder_var.get()

    def get_file_naming(self) -> str:
        return self._naming_var.get()

    def get_generate_hashes(self) -> bool:
        return self._hash_report_var.get()

    def get_generate_timeline(self) -> bool:
        return self._timeline_var.get()

    def get_forensic_log(self) -> bool:
        return self._forensic_log_var.get()
