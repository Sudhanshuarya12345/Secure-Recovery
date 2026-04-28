"""
pyrecovery.cli.wizard — Interactive recovery wizard using Rich.

Single entry point: ``python main.py`` (no subcommand) launches this wizard.
Pure keyboard-driven — no mouse needed.

Flow:
    1. Select source device (enumerate + browse for .img)
    2. Select partition scope
    3. Detect filesystem
    4. Select recovery strategy
    5. Select file types
    6. Select output directory (with safety validation)
    7. Confirm and run
"""

from __future__ import annotations

import os
import shutil
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.table import Table
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeRemainingColumn, TaskProgressColumn, TransferSpeedColumn,
)
from rich.live import Live
from rich.text import Text

from utils.logger import get_logger

logger = get_logger(__name__)
console = Console()


@dataclass
class WizardConfig:
    """Configuration collected by the wizard steps."""
    source: str = ""
    source_display: str = ""
    partition_index: int | None = None
    partition_label: str = ""
    fs_type: str = ""
    fs_label: str = ""
    strategy: str = "both"
    file_types: list[str] = None
    output_dir: str = ""

    def __post_init__(self):
        if self.file_types is None:
            self.file_types = ["all"]


class RecoveryWizard:
    """Interactive CLI wizard for guided file recovery."""

    def run(self) -> None:
        """Execute the full wizard flow."""
        self._print_banner()

        try:
            config = WizardConfig()

            # Step 1: Select source
            config.source, config.source_display = self._step_select_source()

            # Step 2: Select partition
            partitions = self._step_scan_partitions(config.source)
            if partitions:
                config.partition_index, config.partition_label = (
                    self._step_select_partition(partitions)
                )

            # Step 3: Detect filesystem
            config.fs_type, config.fs_label = self._step_detect_filesystem(
                config.source, config.partition_index, partitions
            )

            # Step 4: Strategy
            config.strategy = self._step_select_strategy(config.fs_type)

            # Step 5: File types
            config.file_types = self._step_select_file_types()

            # Step 6: Output directory
            config.output_dir = self._step_select_output(config.source)

            # Step 7: Confirm
            if not self._step_confirm(config):
                console.print("[yellow]Recovery cancelled.[/yellow]")
                return

            # Run recovery
            self._run_recovery(config)

        except KeyboardInterrupt:
            console.print("\n[yellow]Cancelled by user.[/yellow]")
        except Exception as e:
            console.print(f"\n[red]Error: {e}[/red]")

    def _print_banner(self) -> None:
        console.print(Panel(
            "[bold white]PyRecovery — File Recovery Tool[/bold white]\n"
            "[dim]Production-grade disk recovery & digital forensics[/dim]",
            border_style="cyan", padding=(1, 4),
        ))

    # ── Step 1: Source selection ─────────────────────────────────────

    def _step_select_source(self) -> tuple[str, str]:
        """Enumerate devices and let user pick one, or browse for .img."""
        console.print("\n[bold cyan][*] Scanning for available storage devices...[/bold cyan]")

        from disk.platform_devices import list_devices
        devices = list_devices()

        table = Table(show_header=True, header_style="bold cyan",
                      title="Available Devices", border_style="dim")
        table.add_column("#", justify="right", style="bold")
        table.add_column("Device", style="green")
        table.add_column("Model")
        table.add_column("Size", justify="right")
        table.add_column("Type", justify="center")

        for i, dev in enumerate(devices, 1):
            dev_type = "USB" if dev.removable else "Disk"
            table.add_row(str(i), dev.path, dev.model, dev.size_display, dev_type)

        browse_idx = len(devices) + 1
        table.add_row(str(browse_idx), "Browse for image file...",
                       "(select .img/.dd/.raw)", "—", "File")

        console.print(table)

        while True:
            choice = IntPrompt.ask(
                f"\nSelect source device [1-{browse_idx}]",
                default=browse_idx if not devices else 1,
            )
            if 1 <= choice <= len(devices):
                dev = devices[choice - 1]
                return dev.path, f"{dev.path} ({dev.model}, {dev.size_display})"
            elif choice == browse_idx:
                path = Prompt.ask("Enter path to disk image file")
                path = path.strip().strip('"').strip("'")
                if not Path(path).exists():
                    console.print(f"[red]File not found: {path}[/red]")
                    continue
                size = Path(path).stat().st_size
                from utils.size_formatter import format_size
                return path, f"{path} ({format_size(size)})"
            else:
                console.print(f"[red]Invalid choice. Enter 1-{browse_idx}[/red]")

    # ── Step 2: Partition scan ──────────────────────────────────────

    def _step_scan_partitions(self, source: str) -> list:
        """Scan for partitions and return the list."""
        console.print(f"\n[bold cyan][*] Reading partition table on {source}...[/bold cyan]")

        try:
            from disk.reader import DiskReader
            from partition.scanner import PartitionScanner
            from utils.size_formatter import format_size

            with DiskReader(source) as reader:
                scanner = PartitionScanner()
                result = scanner.scan(reader)

            if not result.partitions:
                console.print("[yellow]  No partitions found — will scan entire disk.[/yellow]")
                return []

            table = Table(show_header=True, header_style="bold cyan",
                          title="Partition Table", border_style="dim")
            table.add_column("Option", justify="right", style="bold")
            table.add_column("Description")

            table.add_row("0", "Entire disk (all partitions, raw carving)")
            for p in result.partitions:
                desc = f"Partition {p.index} — {p.fs_type.upper()} — {format_size(p.size_bytes)}"
                if p.label:
                    desc += f" [{p.label}]"
                table.add_row(str(p.index), desc)

            console.print(table)
            return result.partitions

        except Exception as e:
            console.print(f"[yellow]  Partition scan failed: {e}[/yellow]")
            console.print("[yellow]  Will scan entire disk.[/yellow]")
            return []

    def _step_select_partition(self, partitions: list) -> tuple[int | None, str]:
        """Let user pick a partition or entire disk."""
        max_idx = max(p.index for p in partitions)

        choice = IntPrompt.ask(f"\nSelect scope [0-{max_idx}]", default=0)

        if choice == 0:
            return None, "Entire disk"

        for p in partitions:
            if p.index == choice:
                from utils.size_formatter import format_size
                label = f"Partition {p.index} — {p.fs_type.upper()} — {format_size(p.size_bytes)}"
                return p.index, label

        return None, "Entire disk"

    # ── Step 3: Filesystem detection ────────────────────────────────

    def _step_detect_filesystem(
        self, source: str, partition_index: int | None, partitions: list
    ) -> tuple[str, str]:
        """Detect filesystem on the selected partition."""
        console.print("\n[bold cyan][*] Analysing filesystem...[/bold cyan]")

        from filesystem.manager import detect_filesystem, FilesystemInfo
        from utils.size_formatter import format_size

        offset = 0
        if partition_index is not None:
            for p in partitions:
                if p.index == partition_index:
                    offset = p.lba_start * 512
                    break

        info = detect_filesystem(source, offset)

        if info.fs_type != "unknown":
            lines = [f"[green][✓] Detected: {info.display_name}[/green]"]
            if info.label:
                lines.append(f"    Volume label : {info.label}")
            if info.cluster_size:
                lines.append(f"    Cluster size : {info.cluster_size} bytes")
            if info.total_size:
                lines.append(f"    Total space  : {format_size(info.total_size)}")
            if info.free_size:
                lines.append(f"    Free space   : {format_size(info.free_size)}")
            if info.encrypted:
                lines.append(f"    [red]⚠ Volume is ENCRYPTED ({info.version})[/red]")
            console.print("\n".join(lines))
            return info.fs_type, info.label
        else:
            console.print("[yellow]  No filesystem detected — raw carving will be used.[/yellow]")
            return "unknown", ""

    # ── Step 4: Recovery strategy ───────────────────────────────────

    def _step_select_strategy(self, fs_type: str) -> str:
        """Let user choose recovery strategy."""
        console.print("\n[bold]Select recovery strategy:[/bold]")

        if fs_type in ("fat32", "fat16", "ntfs", "ext2", "ext3", "ext4"):
            console.print("  [bold]1[/bold] — Filesystem-aware recovery [green](RECOMMENDED)[/green]")
            console.print("  [bold]2[/bold] — Raw carving only (slower, finds more)")
            console.print("  [bold]3[/bold] — Both (most thorough)")
            choice = IntPrompt.ask("\nStrategy [1-3]", default=3)
            return {1: "filesystem", 2: "carving", 3: "both"}.get(choice, "both")
        else:
            console.print("  [dim]No supported filesystem detected.[/dim]")
            console.print("  [bold]Using raw carving.[/bold]")
            return "carving"

    # ── Step 5: File types ──────────────────────────────────────────

    def _step_select_file_types(self) -> list[str]:
        """Let user select file type categories."""
        console.print("\n[bold]Select file types to recover:[/bold]")
        console.print("  [bold]A[/bold]  All types")
        console.print("  Or choose individually:")
        console.print("  [bold]1[/bold]  Images      (jpg, png, gif, bmp, tiff, webp)")
        console.print("  [bold]2[/bold]  Documents   (pdf, docx, xlsx, pptx, rtf)")
        console.print("  [bold]3[/bold]  Videos      (mp4, avi, mkv, wav)")
        console.print("  [bold]4[/bold]  Audio       (mp3, wav, flac, ogg)")
        console.print("  [bold]5[/bold]  Archives    (zip, rar, 7z, gz)")
        console.print("  [bold]6[/bold]  System      (exe, elf, sqlite, lnk)")

        raw = Prompt.ask("\nEnter choices (e.g. A or 1,2,3)", default="A")
        raw = raw.strip().upper()

        if raw == "A":
            return ["all"]

        type_map = {
            "1": "images", "2": "documents", "3": "media",
            "4": "media", "5": "archives", "6": "system",
        }
        selected = []
        for part in raw.split(","):
            part = part.strip()
            if part in type_map and type_map[part] not in selected:
                selected.append(type_map[part])

        return selected if selected else ["all"]

    # ── Step 6: Output directory ────────────────────────────────────

    def _step_select_output(self, source: str) -> str:
        """Get output directory with safety validation."""
        console.print(f"\n[yellow][!] WARNING: Output location must NOT be "
                       f"the source device ({source})[/yellow]")

        while True:
            output = Prompt.ask("\nEnter output directory",
                                default="./recovered_files")
            output = output.strip().strip('"').strip("'")
            output_path = Path(output).resolve()

            # Safety checks
            errors = self._validate_output(source, str(output_path))
            if errors:
                for err in errors:
                    console.print(f"[red]  ✗ {err}[/red]")
                continue

            # Show free space
            try:
                free = shutil.disk_usage(str(output_path.parent)).free
                from utils.size_formatter import format_size
                console.print(f"[green][✓] Output directory: {output_path} "
                               f"(free space: {format_size(free)} — OK)[/green]")
            except Exception:
                console.print(f"[green][✓] Output directory: {output_path}[/green]")

            return str(output_path)

    def _validate_output(self, source: str, output: str) -> list[str]:
        """Validate output directory is safe to use."""
        errors = []
        output_path = Path(output)

        # Check not same device
        try:
            source_dev = os.stat(source).st_dev
            # For output, check parent dir
            parent = output_path.parent
            if parent.exists():
                output_dev = os.stat(str(parent)).st_dev
                if source_dev == output_dev and not Path(source).is_file():
                    errors.append("Output is on the same device as source!")
        except (OSError, ValueError):
            pass  # Can't check on raw devices — skip

        # Check parent exists or can be created
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            errors.append(f"Cannot create output directory: {e}")

        return errors

    # ── Step 7: Confirm ─────────────────────────────────────────────

    def _step_confirm(self, config: WizardConfig) -> bool:
        """Show summary and get confirmation."""
        strategy_names = {
            "filesystem": "Filesystem-aware only",
            "carving": "Raw carving only",
            "both": "Filesystem-aware + Raw carving",
        }
        type_display = "All types" if "all" in config.file_types else ", ".join(
            t.capitalize() for t in config.file_types
        )

        console.print(Panel(
            f"[bold]Source   :[/bold] {config.source_display}\n"
            f"[bold]Scope    :[/bold] {config.partition_label or 'Entire disk'}\n"
            f"[bold]FS       :[/bold] {config.fs_type.upper() if config.fs_type != 'unknown' else 'None detected'}\n"
            f"[bold]Strategy :[/bold] {strategy_names.get(config.strategy, config.strategy)}\n"
            f"[bold]Types    :[/bold] {type_display}\n"
            f"[bold]Output   :[/bold] {config.output_dir}\n"
            f"[bold]Mode     :[/bold] READ-ONLY (source will not be touched)",
            title="[bold]RECOVERY SUMMARY — Please confirm[/bold]",
            border_style="cyan", padding=(1, 2),
        ))

        return Confirm.ask("\nProceed?", default=False)

    # ── Run recovery ────────────────────────────────────────────────

    def _run_recovery(self, config: WizardConfig) -> None:
        """Launch the recovery engine with Rich progress display."""
        from recovery.engine import (
            RecoveryConfig, RecoveryEngine, EngineCallbacks,
            ProgressData, RecoveryStats, RecoveredFileInfo,
        )
        from utils.size_formatter import format_size

        engine_config = RecoveryConfig(
            source=config.source,
            output_dir=config.output_dir,
            strategy=config.strategy,
            file_types=config.file_types,
            partition_index=config.partition_index,
        )

        # State shared between callback and display
        state = {
            "action": "Starting...",
            "percent": 0.0,
            "speed": 0.0,
            "eta": 0.0,
            "scanned": 0,
            "total": 0,
            "files_by_type": {},
            "done": False,
            "error": None,
            "stats": None,
        }
        lock = threading.Lock()

        def on_progress(data: ProgressData):
            with lock:
                state["action"] = data.current_action
                state["percent"] = data.percent
                state["speed"] = data.speed_bps
                state["eta"] = data.eta_seconds
                state["scanned"] = data.bytes_scanned
                state["total"] = data.total_bytes

        def on_file_found(info: RecoveredFileInfo):
            with lock:
                ext = info.extension
                state["files_by_type"][ext] = state["files_by_type"].get(ext, 0) + 1

        def on_log(level: str, msg: str):
            pass  # Progress bar handles display

        def on_complete(stats: RecoveryStats):
            with lock:
                state["done"] = True
                state["stats"] = stats

        def on_error(msg: str):
            with lock:
                state["error"] = msg
                state["done"] = True

        callbacks = EngineCallbacks(
            on_progress=on_progress,
            on_file_found=on_file_found,
            on_log=on_log,
            on_complete=on_complete,
            on_error=on_error,
        )

        engine = RecoveryEngine(engine_config, callbacks)

        # Start engine in background thread
        thread = threading.Thread(target=engine.start, daemon=True)
        thread.start()

        # Display progress with Rich
        console.print("\n[bold cyan][*] Starting recovery...[/bold cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40),
            TaskProgressColumn(),
            TextColumn("•"),
            TransferSpeedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning", total=100)

            while not state["done"]:
                with lock:
                    progress.update(
                        task,
                        completed=state["percent"],
                        description=state["action"][:50],
                    )

                    # Build type counts line
                    type_parts = []
                    for ext, count in sorted(state["files_by_type"].items()):
                        type_parts.append(f"{ext}:{count}")

                    if type_parts:
                        type_line = "  Found: " + "  ".join(type_parts)
                    else:
                        type_line = ""

                import time
                time.sleep(0.25)

            # Final update
            progress.update(task, completed=100, description="Complete")

        # Show results
        if state["error"]:
            console.print(f"\n[red][✗] Recovery failed: {state['error']}[/red]")
            return

        stats = state["stats"]
        if stats:
            # File type summary
            if stats.files_by_type:
                type_parts = []
                for ext, count in sorted(stats.files_by_type.items()):
                    type_parts.append(f"[bold]{ext}[/bold]:{count}")
                console.print(f"\n  Found: {' | '.join(type_parts)}")

            console.print(Panel(
                f"[bold green][✓] Recovery complete in {stats.duration_seconds:.0f}s[/bold green]\n\n"
                f"[bold]Files recovered :[/bold] {stats.total_files}\n"
                f"[bold]From filesystem :[/bold] {stats.files_from_filesystem}\n"
                f"[bold]From carving    :[/bold] {stats.files_from_carving}\n"
                f"[bold]Output folder   :[/bold] {stats.output_dir}\n"
                + (f"[bold]Report saved    :[/bold] {stats.report_path}\n"
                   if stats.report_path else ""),
                title="[bold cyan]Recovery Results[/bold cyan]",
                border_style="green", padding=(1, 2),
            ))
