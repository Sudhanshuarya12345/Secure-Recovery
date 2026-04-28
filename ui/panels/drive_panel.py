"""
pyrecovery.ui.panels.drive_panel — Drive selection and recovery control panel.

Contains:
    - Refresh Drives button
    - Drive list (Treeview)
    - Selected drive details
    - Scope radio buttons (Entire disk / Partition)
    - Output directory entry + Browse
    - Start / Stop / Generate Report buttons
    - Embedded ProgressPanel at the bottom
"""

from __future__ import annotations

import os
import shutil
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
from typing import Optional

from ui.panels.progress_panel import ProgressPanel


class DrivePanel(ttk.Frame):
    """Drive selection tab — the main operational panel."""

    def __init__(self, parent: tk.Widget, app, **kwargs):
        super().__init__(parent, **kwargs)
        self._app = app  # Reference to PyRecoveryApp for thread-safe updates
        self._devices: list = []
        self._partitions: list = []
        self._selected_device = None
        self._selected_device_path: str = ""
        self._scope_var = tk.StringVar(value="disk")
        self._output_var = tk.StringVar(value=str(Path.cwd() / "recovered_files"))
        self._recovery_thread: threading.Thread | None = None
        self._engine = None
        self._build()

    def _build(self) -> None:
        # ── Top: Refresh button ─────────────────────────────────────
        top_frame = ttk.Frame(self)
        top_frame.pack(fill="x", padx=8, pady=(8, 4))

        self._refresh_btn = ttk.Button(top_frame, text="⟳ Refresh Drives",
                                        command=self._refresh_drives)
        self._refresh_btn.pack(side="left")

        self._status_label = ttk.Label(top_frame, text="",
                                        font=("Segoe UI", 9), foreground="#888")
        self._status_label.pack(side="left", padx=12)

        ttk.Button(top_frame, text="Browse Image File...",
                    command=self._browse_image).pack(side="right")

        # ── Drive list ──────────────────────────────────────────────
        ttk.Label(self, text="Available Drives",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=8, pady=(4, 2))

        tree_frame = ttk.Frame(self)
        tree_frame.pack(fill="x", padx=8, pady=(0, 4))

        columns = ("device", "label", "filesystem", "size", "type")
        self._tree = ttk.Treeview(tree_frame, columns=columns,
                                   show="headings", height=5,
                                   selectmode="browse")
        self._tree.heading("device", text="Drive")
        self._tree.heading("label", text="Label")
        self._tree.heading("filesystem", text="Filesystem")
        self._tree.heading("size", text="Size")
        self._tree.heading("type", text="Type")

        self._tree.column("device", width=100)
        self._tree.column("label", width=180)
        self._tree.column("filesystem", width=80, anchor="center")
        self._tree.column("size", width=100, anchor="e")
        self._tree.column("type", width=120, anchor="center")

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical",
                                   command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)
        self._tree.pack(side="left", fill="x", expand=True)
        scrollbar.pack(side="right", fill="y")

        self._tree.bind("<<TreeviewSelect>>", self._on_drive_selected)

        # ── Details panel ───────────────────────────────────────────
        ttk.Label(self, text="Selected Drive Details",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=8, pady=(4, 2))

        self._details_frame = ttk.LabelFrame(self, text="", padding=6)
        self._details_frame.pack(fill="x", padx=8, pady=(0, 4))

        self._detail_labels = {}
        for field in ["Device Path", "Model", "Size", "Filesystem", "Partitions"]:
            row = ttk.Frame(self._details_frame)
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=f"{field} :", font=("Segoe UI", 9, "bold"),
                      width=14, anchor="e").pack(side="left")
            lbl = ttk.Label(row, text="—", font=("Segoe UI", 9))
            lbl.pack(side="left", padx=(8, 0))
            self._detail_labels[field] = lbl

        # ── Scope radio buttons ─────────────────────────────────────
        scope_frame = ttk.Frame(self)
        scope_frame.pack(fill="x", padx=8, pady=4)

        ttk.Label(scope_frame, text="Scope:",
                  font=("Segoe UI", 9, "bold")).pack(side="left")

        self._scope_disk_rb = ttk.Radiobutton(
            scope_frame, text="Entire Disk", variable=self._scope_var, value="disk"
        )
        self._scope_disk_rb.pack(side="left", padx=(8, 4))

        self._scope_part_rb = ttk.Radiobutton(
            scope_frame, text="Partition 1", variable=self._scope_var, value="part_0"
        )
        self._scope_part_rb.pack(side="left", padx=4)

        # ── Output directory ────────────────────────────────────────
        output_frame = ttk.Frame(self)
        output_frame.pack(fill="x", padx=8, pady=4)

        ttk.Label(output_frame, text="Output Directory:",
                  font=("Segoe UI", 9, "bold")).pack(side="left")

        self._output_entry = ttk.Entry(output_frame, textvariable=self._output_var,
                                        width=50)
        self._output_entry.pack(side="left", padx=(8, 4), fill="x", expand=True)

        ttk.Button(output_frame, text="Browse...",
                    command=self._browse_output).pack(side="left")

        # Safety warning
        ttk.Label(self, text="⚠ Output must not be on the same device as source",
                  font=("Segoe UI", 8), foreground="#E65100").pack(anchor="w", padx=8)

        # ── Action buttons ──────────────────────────────────────────
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill="x", padx=8, pady=8)

        self._start_btn = ttk.Button(btn_frame, text="▶ Start Recovery",
                                      command=self._start_recovery)
        self._start_btn.pack(side="left", padx=(0, 8))

        self._stop_btn = ttk.Button(btn_frame, text="■ Stop",
                                     command=self._stop_recovery, state="disabled")
        self._stop_btn.pack(side="left", padx=(0, 8))

        self._report_btn = ttk.Button(btn_frame, text="📄 Generate Report",
                                       command=self._generate_report, state="disabled")
        self._report_btn.pack(side="right")

        # ── Progress panel ──────────────────────────────────────────
        self._progress = ProgressPanel(self)
        self._progress.pack(fill="x", padx=0, pady=0)

    # ── Device enumeration ──────────────────────────────────────────

    def _refresh_drives(self) -> None:
        """Refresh device list in a background thread."""
        self._refresh_btn.config(state="disabled")
        self._status_label.config(text="Scanning...")

        def _scan():
            from disk.platform_devices import list_devices
            devices = list_devices()
            self._app.root.after(0, lambda: self._populate_drives(devices))

        threading.Thread(target=_scan, daemon=True).start()

    def _populate_drives(self, devices: list) -> None:
        """Populate the drive treeview (called from main thread)."""
        self._devices = devices
        self._tree.delete(*self._tree.get_children())

        for dev in devices:
            dev_type = "USB/Removable" if dev.removable else "Fixed Disk"
            label = dev.label if dev.label else dev.model
            fs = dev.fs_type if dev.fs_type else "—"
            self._tree.insert("", "end", values=(
                dev.path, label, fs, dev.size_display, dev_type
            ))

        self._refresh_btn.config(state="normal")
        count = len(devices)
        if count == 0:
            self._status_label.config(
                text="No devices found — try Run as Administrator, or Browse for image file"
            )
        else:
            self._status_label.config(
                text=f"Found {count} drive{'s' if count != 1 else ''}"
            )

    def _browse_image(self) -> None:
        """Browse for a disk image file."""
        path = filedialog.askopenfilename(
            title="Select Disk Image",
            filetypes=[
                ("Disk images", "*.img *.dd *.raw *.E01 *.iso"),
                ("All files", "*.*"),
            ],
        )
        if path:
            self._set_image_source(path)

    def _set_image_source(self, path: str) -> None:
        """Set an image file as the source."""
        size = Path(path).stat().st_size
        from utils.size_formatter import format_size

        self._selected_device_path = path
        self._detail_labels["Device Path"].config(text=path)
        self._detail_labels["Model"].config(text="Image file")
        self._detail_labels["Size"].config(text=format_size(size))
        self._detail_labels["Filesystem"].config(text="Detecting...")

        # Detect filesystem in background
        def _detect():
            from filesystem.manager import detect_filesystem
            info = detect_filesystem(path)
            self._app.root.after(0, lambda: self._detail_labels["Filesystem"].config(
                text=info.display_name
            ))

        threading.Thread(target=_detect, daemon=True).start()

    # ── Drive selection ─────────────────────────────────────────────

    def _on_drive_selected(self, event) -> None:
        """Handle drive selection in treeview."""
        selection = self._tree.selection()
        if not selection:
            return

        item = self._tree.item(selection[0])
        values = item["values"]
        device_path = str(values[0])
        self._selected_device_path = device_path

        self._detail_labels["Device Path"].config(text=device_path)
        self._detail_labels["Model"].config(text=str(values[1]))
        self._detail_labels["Size"].config(text=str(values[2]))

        # Detect FS and partitions in background
        self._detail_labels["Filesystem"].config(text="Detecting...")
        self._detail_labels["Partitions"].config(text="Scanning...")

        def _detect():
            from filesystem.manager import detect_filesystem
            fs_info = detect_filesystem(device_path)

            # Try partition scan
            part_text = "—"
            try:
                from disk.reader import DiskReader
                from partition.scanner import PartitionScanner
                from utils.size_formatter import format_size
                with DiskReader(device_path) as reader:
                    scanner = PartitionScanner()
                    result = scanner.scan(reader)
                    self._partitions = result.partitions
                    if result.partitions:
                        parts = []
                        for p in result.partitions:
                            parts.append(
                                f"P{p.index} — {p.fs_type.upper()} — "
                                f"{format_size(p.size_bytes)}"
                            )
                        part_text = "; ".join(parts)
                    else:
                        part_text = "None found"
            except Exception as e:
                part_text = f"Error: {e}"

            self._app.root.after(0, lambda: self._update_drive_details(
                fs_info.display_name, part_text
            ))

        threading.Thread(target=_detect, daemon=True).start()

    def _update_drive_details(self, fs_name: str, part_text: str) -> None:
        """Update detail labels from main thread."""
        self._detail_labels["Filesystem"].config(text=fs_name)
        self._detail_labels["Partitions"].config(text=part_text)

        # Update scope radio buttons
        if self._partitions:
            from utils.size_formatter import format_size
            p = self._partitions[0]
            self._scope_part_rb.config(
                text=f"Partition {p.index} — {p.fs_type.upper()} — "
                     f"{format_size(p.size_bytes)}"
            )

    # ── Output directory ────────────────────────────────────────────

    def _browse_output(self) -> None:
        """Browse for output directory."""
        path = filedialog.askdirectory(title="Select Output Directory")
        if path:
            self._output_var.set(path)

    # ── Recovery control ────────────────────────────────────────────

    def _start_recovery(self) -> None:
        """Validate config and start recovery in background thread."""
        source = self._selected_device_path
        if not source:
            messagebox.showerror("Error", "No source device selected.\n"
                                          "Select a drive or browse for an image file.")
            return

        output = self._output_var.get().strip()
        if not output:
            messagebox.showerror("Error", "Please specify an output directory.")
            return

        # Safety: check output not on same device
        try:
            if Path(source).is_file():
                src_dev = os.stat(source).st_dev
                out_parent = Path(output).parent
                out_parent.mkdir(parents=True, exist_ok=True)
                out_dev = os.stat(str(out_parent)).st_dev
                if src_dev == out_dev:
                    messagebox.showwarning("Warning",
                        "Output directory is on the same drive as the source image.\n"
                        "This is allowed for image files but not recommended."
                    )
        except OSError:
            pass

        # Confirmation
        if not messagebox.askyesno("Confirm Recovery",
            f"Source: {source}\n"
            f"Output: {output}\n\n"
            f"Mode: READ-ONLY (source will not be modified)\n\n"
            "Proceed with recovery?"):
            return

        # Disable controls
        self._start_btn.config(state="disabled")
        self._stop_btn.config(state="normal")
        self._refresh_btn.config(state="disabled")
        self._progress.reset()

        # Build config
        from recovery.engine import RecoveryConfig, RecoveryEngine, EngineCallbacks

        # Get settings from other panels
        filetype_panel = self._app.filetype_panel
        settings_panel = self._app.settings_panel

        config = RecoveryConfig(
            source=source,
            output_dir=output,
            strategy=filetype_panel.get_strategy(),
            file_types=filetype_panel.get_selected_categories(),
            partition_index=self._get_partition_index(),
            chunk_size=settings_panel.get_chunk_size(),
            skip_duplicates=settings_panel.get_skip_duplicates(),
            save_partials=settings_panel.get_save_partials(),
            max_file_size=settings_panel.get_max_file_size(),
            folder_structure=settings_panel.get_folder_structure(),
            file_naming=settings_panel.get_file_naming(),
            generate_hashes=settings_panel.get_generate_hashes(),
            generate_timeline=settings_panel.get_generate_timeline(),
            forensic_log=settings_panel.get_forensic_log(),
        )

        # State dict for thread-safe updates
        self._progress_state = {
            "files_by_type": {},
            "total_files": 0,
        }

        callbacks = EngineCallbacks(
            on_progress=lambda data: self._app.root.after(0, lambda d=data: self._on_progress(d)),
            on_file_found=lambda f: self._app.root.after(0, lambda fi=f: self._on_file_found(fi)),
            on_log=lambda lvl, msg: self._app.root.after(0, lambda l=lvl, m=msg: self._on_log(l, m)),
            on_complete=lambda s: self._app.root.after(0, lambda st=s: self._on_complete(st)),
            on_error=lambda e: self._app.root.after(0, lambda er=e: self._on_error(er)),
        )

        self._engine = RecoveryEngine(config, callbacks)
        self._recovery_thread = threading.Thread(target=self._engine.start, daemon=True)
        self._recovery_thread.start()

        self._on_log("INFO", f"Recovery started: {source}")

    def _stop_recovery(self) -> None:
        """Stop recovery gracefully."""
        if self._engine:
            self._engine.stop()
            self._on_log("WARN", "Stop signal sent — waiting for engine to finish...")

    def _get_partition_index(self) -> int | None:
        """Get selected partition index, or None for entire disk."""
        scope = self._scope_var.get()
        if scope == "disk":
            return None
        try:
            return int(scope.split("_")[1])
        except (IndexError, ValueError):
            return None

    # ── Callbacks (all called from main thread via root.after) ──────

    def _on_progress(self, data) -> None:
        """Update progress panel."""
        self._progress.update_progress(
            percent=data.percent,
            current_action=data.current_action,
            speed_bps=data.speed_bps,
            eta_seconds=data.eta_seconds,
            bytes_scanned=data.bytes_scanned,
            total_bytes=data.total_bytes,
            files_by_type=self._progress_state["files_by_type"],
            total_files=self._progress_state["total_files"],
        )

    def _on_file_found(self, info) -> None:
        """Handle file found event."""
        ext = info.extension
        self._progress_state["files_by_type"][ext] = (
            self._progress_state["files_by_type"].get(ext, 0) + 1
        )
        self._progress_state["total_files"] += 1
        self._on_log("FOUND", f"{info.extension} @ offset 0x{info.offset:08X} ({info.size:,} bytes)")

    def _on_log(self, level: str, message: str) -> None:
        """Forward log to the log panel."""
        self._app.log_panel.add_entry(level, message)

    def _on_complete(self, stats) -> None:
        """Handle recovery completion."""
        self._start_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._refresh_btn.config(state="normal")
        self._report_btn.config(state="normal")

        self._progress.set_complete(stats.total_files, stats.duration_seconds)

        self._on_log("INFO",
            f"Recovery complete: {stats.total_files} files "
            f"({stats.files_from_filesystem} FS + {stats.files_from_carving} carved) "
            f"in {stats.duration_seconds:.1f}s"
        )

        messagebox.showinfo("Recovery Complete",
            f"Files recovered: {stats.total_files}\n"
            f"Output: {stats.output_dir}\n"
            f"Duration: {stats.duration_seconds:.1f}s"
        )

    def _on_error(self, error: str) -> None:
        """Handle engine error."""
        self._start_btn.config(state="normal")
        self._stop_btn.config(state="disabled")
        self._refresh_btn.config(state="normal")

        self._on_log("ERROR", error)
        messagebox.showerror("Recovery Error", error)

    def _generate_report(self) -> None:
        """Generate forensic report for the last recovery."""
        messagebox.showinfo("Report",
                             "Report was saved automatically during recovery.\n"
                             "Check the output directory for recovery_report.json")
