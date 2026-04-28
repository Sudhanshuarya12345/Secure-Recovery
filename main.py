"""
PyRecovery — Production-grade disk recovery & digital forensics tool.

Entry points:
    python main.py          →  Interactive CLI wizard (guided recovery)
    python main.py --ui     →  Tkinter graphical interface
    python main.py <cmd>    →  Click subcommands (carve, recover, scan, etc.)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Fix Windows console encoding for Rich Unicode output
if os.name == "nt":
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from utils.logger import setup_logging, get_logger

console = Console()
logger = get_logger(__name__)


@click.group()
@click.option("--verbose", is_flag=True, help="Enable debug logging")
@click.option("--log-file", type=str, default=None, help="Path to forensic log file")
@click.option("--readonly/--no-readonly", default=True, help="Enforce read-only mode (default: true)")
@click.version_option(version="1.0.0", prog_name="pyrecovery")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, log_file: str | None, readonly: bool) -> None:
    """PyRecovery — Production-grade disk recovery & digital forensics tool.

    Recover deleted files, carve data from damaged media, and analyze disk images
    with forensic-grade integrity guarantees.
    """
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["readonly"] = readonly
    setup_logging(
        level="DEBUG" if verbose else "INFO",
        log_file=log_file,
        forensic_mode=log_file is not None,
    )


@cli.command("test-read")
@click.argument("source", type=click.Path(exists=True))
@click.option("--sector", "-s", type=int, default=0, help="Sector number to read")
@click.option("--count", "-n", type=int, default=1, help="Number of sectors to read")
def test_read(source: str, sector: int, count: int) -> None:
    """Test reading a disk or image file. Displays hex dump of specified sectors."""
    from disk.reader import DiskReader
    from utils.hex_utils import hex_dump
    from utils.size_formatter import format_size

    try:
        with DiskReader(source) as reader:
            # Display source info
            console.print(Panel(
                f"[bold]Source:[/bold] {source}\n"
                f"[bold]Size:[/bold] {format_size(reader.get_disk_size())} "
                f"({reader.get_disk_size():,} bytes)\n"
                f"[bold]Sectors:[/bold] {reader.get_sector_count():,}\n"
                f"[bold]Sector size:[/bold] {reader.sector_size} bytes\n"
                f"[bold]Device:[/bold] {reader.is_device}\n"
                f"[bold]mmap:[/bold] {reader.uses_mmap}",
                title="[bold cyan]PyRecovery — Disk Reader[/bold cyan]",
                border_style="cyan",
            ))

            # Read and display requested sectors
            data = reader.read_sectors(sector, count)
            console.print(f"\n[bold]Sector {sector}" +
                          (f"–{sector + count - 1}" if count > 1 else "") +
                          f" ({len(data)} bytes):[/bold]\n")
            console.print(hex_dump(data, offset=sector * reader.sector_size))

            if reader.bad_sectors.count > 0:
                console.print(
                    f"\n[yellow]WARNING: Bad sectors encountered: "
                    f"{reader.bad_sectors.count}[/yellow]"
                )
    except (PermissionError, FileNotFoundError) as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@cli.command("list-devices")
def list_devices_cmd() -> None:
    """List detected physical storage devices."""
    from disk.platform_devices import list_devices

    devices = list_devices()

    if not devices:
        console.print("[yellow]No devices found. You may need elevated privileges.[/yellow]")
        return

    table = Table(
        title="Detected Storage Devices",
        show_header=True,
        header_style="bold cyan",
    )
    table.add_column("Path", style="green")
    table.add_column("Size", justify="right")
    table.add_column("Model")
    table.add_column("Removable", justify="center")
    table.add_column("Partitions", justify="right")

    for dev in devices:
        table.add_row(
            dev.path,
            dev.size_display,
            dev.model,
            "✓" if dev.removable else "—",
            str(len(dev.partitions)),
        )

    console.print(table)


@cli.command("create-image")
@click.option("--source", "-s", required=True, help="Source device or image path")
@click.option("--output", "-o", required=True, help="Output image file path")
@click.option("--chunk-size", type=str, default="1M", help="Read chunk size (e.g., 1M, 512K)")
def create_image(source: str, output: str, chunk_size: str) -> None:
    """Create a forensic disk image with integrity hashes."""
    from disk.imager import DiskImager
    from utils.size_formatter import parse_size, format_size
    from tqdm import tqdm

    try:
        chunk = parse_size(chunk_size)
    except ValueError as e:
        console.print(f"[red]Invalid chunk size: {e}[/red]")
        sys.exit(1)

    console.print(f"[bold cyan]Creating forensic image:[/bold cyan] {source} → {output}")

    pbar = tqdm(total=100, desc="Imaging", unit="%", bar_format=(
        "{l_bar}{bar}| {n:.0f}%/{total:.0f}% | {elapsed}<{remaining}"
    ))

    last_pct = [0]
    def progress(current: int, total: int) -> None:
        pct = int((current / total) * 100) if total > 0 else 0
        if pct > last_pct[0]:
            pbar.update(pct - last_pct[0])
            last_pct[0] = pct

    try:
        result = DiskImager.create_image(
            source=source, dest_path=output,
            chunk_size=chunk, progress_callback=progress,
        )
        pbar.close()

        console.print(Panel(
            f"[bold green][OK] Image created successfully[/bold green]\n\n"
            f"[bold]Output:[/bold] {result.dest_path}\n"
            f"[bold]Size:[/bold] {format_size(result.total_bytes)}\n"
            f"[bold]SHA256:[/bold] {result.sha256}\n"
            f"[bold]Duration:[/bold] {result.duration_seconds:.1f}s\n"
            f"[bold]Throughput:[/bold] {result.throughput_mbps:.1f} MB/s\n"
            f"[bold]Bad sectors:[/bold] {result.bad_sector_count}",
            title="[bold cyan]Imaging Result[/bold cyan]",
            border_style="green",
        ))
    except (PermissionError, FileNotFoundError) as e:
        pbar.close()
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@cli.command("verify-image")
@click.argument("image", type=click.Path(exists=True))
@click.option("--hashlog", type=click.Path(exists=True), default=None, help="Path to hashlog file")
def verify_image(image: str, hashlog: str | None) -> None:
    """Verify a forensic image against its hashlog."""
    from disk.imager import DiskImager

    console.print(f"[bold cyan]Verifying image:[/bold cyan] {image}")

    result = DiskImager.verify_image(image, hashlog)

    if result.valid:
        console.print(Panel(
            f"[bold green][OK] Verification PASSED[/bold green]\n\n"
            f"[bold]SHA256:[/bold] {result.computed_sha256}\n"
            f"[bold]Blocks verified:[/bold] {result.total_blocks}",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red][FAIL] Verification FAILED[/bold red]\n\n"
            f"[bold]Reason:[/bold] {result.message}\n"
            f"[bold]Expected SHA256:[/bold] {result.expected_sha256}\n"
            f"[bold]Computed SHA256:[/bold] {result.computed_sha256}\n"
            f"[bold]Failed blocks:[/bold] {result.failed_blocks}",
            border_style="red",
        ))
        sys.exit(1)


@cli.command("carve")
@click.argument("source", type=click.Path(exists=True))
@click.option("--output", "-o", default="./recovered", help="Output directory for recovered files")
@click.option("--no-dedup", is_flag=True, help="Disable duplicate suppression")
@click.option("--chunk-size", type=str, default="1M", help="Read chunk size")
def carve_cmd(source: str, output: str, no_dedup: bool, chunk_size: str) -> None:
    """Carve files from a disk image using signature-based detection."""
    from carving.engine import CarvingEngine
    from carving.registry import SignatureRegistry
    from utils.size_formatter import format_size, parse_size
    from tqdm import tqdm

    try:
        chunk = parse_size(chunk_size)
    except ValueError as e:
        console.print(f"[red]Invalid chunk size: {e}[/red]")
        sys.exit(1)

    registry = SignatureRegistry()
    registry.register_builtins()

    console.print(Panel(
        f"[bold]Source:[/bold] {source}\n"
        f"[bold]Output:[/bold] {output}\n"
        f"[bold]Signatures loaded:[/bold] {registry.count}\n"
        f"[bold]Deduplication:[/bold] {'disabled' if no_dedup else 'enabled'}",
        title="[bold cyan]PyRecovery — File Carving[/bold cyan]",
        border_style="cyan",
    ))

    pbar = tqdm(total=100, desc="Carving", unit="%", bar_format=(
        "{l_bar}{bar}| {n:.0f}% | Files: {postfix} | {elapsed}<{remaining}"
    ))

    last_pct = [0]
    def progress(scanned: int, total: int, files: int) -> None:
        pct = int((scanned / total) * 100) if total > 0 else 0
        if pct > last_pct[0]:
            pbar.update(pct - last_pct[0])
            last_pct[0] = pct
        pbar.set_postfix_str(str(files))

    try:
        engine = CarvingEngine(
            registry, output_dir=output, chunk_size=chunk,
            enable_dedup=not no_dedup, progress_callback=progress,
        )
        result = engine.carve(source)
        pbar.close()

        # Results table
        table = Table(title="Recovered Files by Type", show_header=True,
                      header_style="bold cyan")
        table.add_column("Extension", style="green")
        table.add_column("Count", justify="right")
        for ext, count in sorted(result.files_by_type.items()):
            table.add_row(f".{ext}", str(count))
        console.print(table)

        console.print(Panel(
            f"[bold green][OK] Carving complete[/bold green]\n\n"
            f"[bold]Files found:[/bold] {result.files_found}\n"
            f"[bold]Valid files:[/bold] {result.files_valid}\n"
            f"[bold]Rejected (false positives):[/bold] {result.files_rejected}\n"
            f"[bold]Duplicates suppressed:[/bold] {result.files_duplicate}\n"
            f"[bold]Duration:[/bold] {result.duration_seconds:.1f}s\n"
            f"[bold]Throughput:[/bold] "
            f"{(result.total_bytes_scanned / 1048576) / max(result.duration_seconds, 0.1):.1f} MB/s",
            title="[bold cyan]Carving Results[/bold cyan]",
            border_style="green",
        ))
    except (PermissionError, FileNotFoundError) as e:
        pbar.close()
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@cli.command("scan")
@click.argument("source", type=click.Path(exists=True))
def scan_cmd(source: str) -> None:
    """Scan a disk or image for partitions and identify filesystems."""
    from disk.reader import DiskReader
    from partition.scanner import PartitionScanner
    from utils.size_formatter import format_size

    try:
        with DiskReader(source) as reader:
            scanner = PartitionScanner()
            result = scanner.scan(reader)

            console.print(Panel(
                f"[bold]Source:[/bold] {source}\n"
                f"[bold]Size:[/bold] {format_size(result.disk_size)}\n"
                f"[bold]Scheme:[/bold] {result.scheme.upper()}\n"
                f"[bold]Partitions:[/bold] {len(result.partitions)}\n"
                f"[bold]Unallocated gaps:[/bold] {len(result.unallocated)}",
                title="[bold cyan]PyRecovery -- Partition Scan[/bold cyan]",
                border_style="cyan",
            ))

            if result.partitions:
                table = Table(
                    title="Detected Partitions",
                    show_header=True,
                    header_style="bold cyan",
                )
                table.add_column("#", justify="right")
                table.add_column("Type")
                table.add_column("Filesystem", style="green")
                table.add_column("Label")
                table.add_column("LBA Start", justify="right")
                table.add_column("Size", justify="right")
                table.add_column("Boot", justify="center")

                for p in result.partitions:
                    table.add_row(
                        str(p.index),
                        p.type_name,
                        p.fs_type,
                        p.label or "--",
                        str(p.lba_start),
                        format_size(p.size_bytes),
                        "Y" if p.bootable else "",
                    )
                console.print(table)

            if result.unallocated:
                console.print(f"\n[yellow]Unallocated regions:[/yellow]")
                for start, end in result.unallocated:
                    gap_size = (end - start + 1) * 512
                    console.print(f"  LBA {start}--{end} ({format_size(gap_size)})")

    except (PermissionError, FileNotFoundError) as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@cli.command("recover")
@click.argument("source", type=click.Path(exists=True))
@click.option("--output", "-o", default="./recovered", help="Output directory")
@click.option("--method", type=click.Choice(["auto", "filesystem", "carving", "all"]),
              default="auto", help="Recovery method")
@click.option("--no-deleted", is_flag=True, help="Skip deleted file recovery")
@click.option("--no-carving", is_flag=True, help="Disable carving fallback")
def recover_cmd(
    source: str, output: str, method: str, no_deleted: bool, no_carving: bool
) -> None:
    """Recover files from a disk image using filesystem + carving."""
    from recovery.strategy import RecoveryStrategy
    from utils.size_formatter import format_size

    console.print(Panel(
        f"[bold]Source:[/bold] {source}\n"
        f"[bold]Output:[/bold] {output}\n"
        f"[bold]Method:[/bold] {method}\n"
        f"[bold]Include deleted:[/bold] {'no' if no_deleted else 'yes'}\n"
        f"[bold]Carving:[/bold] {'disabled' if no_carving else 'enabled'}",
        title="[bold cyan]PyRecovery -- File Recovery[/bold cyan]",
        border_style="cyan",
    ))

    def progress(phase: str, current: int, total: int) -> None:
        if total > 0:
            pct = int(current / total * 100)
            console.print(f"  [{phase}] {pct}%", end="\r")

    try:
        strategy = RecoveryStrategy(
            output_dir=output,
            include_deleted=not no_deleted,
            enable_carving=not no_carving,
            progress_callback=progress,
        )
        result = strategy.recover(source, method=method)

        # Results table
        if result.recovered_files:
            table = Table(
                title="Recovered Files",
                show_header=True,
                header_style="bold cyan",
            )
            table.add_column("Path", style="green")
            table.add_column("Size", justify="right")
            table.add_column("Source")
            table.add_column("Deleted", justify="center")

            for f in result.recovered_files[:50]:  # Cap display at 50
                table.add_row(
                    f.path,
                    format_size(f.size),
                    f.source,
                    "Y" if f.is_deleted else "",
                )
            if len(result.recovered_files) > 50:
                table.add_row("...", "...", "...", "...")
            console.print(table)

        console.print(Panel(
            f"[bold green][OK] Recovery complete[/bold green]\n\n"
            f"[bold]Total files:[/bold] {result.total_files}\n"
            f"[bold]From filesystem:[/bold] {result.files_from_filesystem}\n"
            f"[bold]From carving:[/bold] {result.files_from_carving}\n"
            f"[bold]Partitions found:[/bold] {result.partitions_found}\n"
            f"[bold]Partition scheme:[/bold] {result.partition_scheme}\n"
            f"[bold]Duration:[/bold] {result.duration_seconds:.1f}s",
            title="[bold cyan]Recovery Results[/bold cyan]",
            border_style="green",
        ))
    except (PermissionError, FileNotFoundError) as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@cli.command("analyze")
@click.argument("source", type=click.Path(exists=True))
@click.option("--output", "-o", default="./forensic_output", help="Output directory")
@click.option("--case-id", default="", help="Case identifier")
@click.option("--examiner", default="", help="Examiner name")
@click.option("--bundle", is_flag=True, help="Create evidence bundle")
@click.option("--zip", "create_zip", is_flag=True, help="Also create ZIP archive")
def analyze_cmd(
    source: str, output: str, case_id: str, examiner: str,
    bundle: bool, create_zip: bool,
) -> None:
    """Run full forensic analysis: recover, analyze timeline, generate report."""
    from disk.reader import DiskReader
    from partition.scanner import PartitionScanner
    from recovery.strategy import RecoveryStrategy
    from forensics.chain_of_custody import ChainOfCustody
    from forensics.hasher import ForensicHasher
    from forensics.timeline import ForensicTimeline
    from forensics.report_generator import ReportGenerator
    from forensics.evidence_packager import EvidencePackager
    from utils.size_formatter import format_size

    output_dir = Path(output)
    output_dir.mkdir(parents=True, exist_ok=True)

    console.print(Panel(
        f"[bold]Source:[/bold] {source}\n"
        f"[bold]Output:[/bold] {output}\n"
        f"[bold]Case ID:[/bold] {case_id or 'N/A'}\n"
        f"[bold]Examiner:[/bold] {examiner or 'N/A'}",
        title="[bold cyan]PyRecovery -- Forensic Analysis[/bold cyan]",
        border_style="cyan",
    ))

    # Initialize chain of custody
    coc = ChainOfCustody(str(output_dir / "chain_of_custody.jsonl"), operator=examiner)
    coc.log_action("analysis_started", {
        "source": source, "case_id": case_id,
    })

    try:
        # Phase 1: Hash source
        console.print("[dim]Hashing source...[/dim]")
        source_hash = ForensicHasher.hash_file(source)
        coc.log_action("source_hashed", {
            "sha256": source_hash.sha256, "md5": source_hash.md5,
        })
        console.print(f"  SHA256: [green]{source_hash.sha256}[/green]")

        # Phase 2: Partition scan
        console.print("[dim]Scanning partitions...[/dim]")
        with DiskReader(source) as reader:
            scanner = PartitionScanner()
            scan_result = scanner.scan(reader)
        coc.log_action("partitions_scanned", {
            "scheme": scan_result.scheme,
            "count": len(scan_result.partitions),
        })
        console.print(f"  Found {len(scan_result.partitions)} partition(s) [{scan_result.scheme.upper()}]")

        # Phase 3: Recovery
        console.print("[dim]Recovering files...[/dim]")
        strategy = RecoveryStrategy(output_dir=str(output_dir / "recovered"))
        recovery_result = strategy.recover(source, method="auto")
        coc.log_action("recovery_completed", {
            "total_files": recovery_result.total_files,
            "from_fs": recovery_result.files_from_filesystem,
            "from_carving": recovery_result.files_from_carving,
        })
        console.print(f"  Recovered {recovery_result.total_files} file(s)")

        # Phase 4: Timeline
        console.print("[dim]Building forensic timeline...[/dim]")
        timeline = ForensicTimeline()
        # Note: In production, timestamps from actual FS entries would be added here.
        # For now, the timeline is populated during filesystem recovery.
        anomalies = timeline.detect_anomalies()
        timeline.export_csv(str(output_dir / "timeline.csv"))
        timeline.export_json(str(output_dir / "timeline.json"))
        console.print(f"  {timeline.event_count} event(s), {len(anomalies)} anomaly(ies)")

        # Phase 5: Hash manifest
        console.print("[dim]Generating hash manifest...[/dim]")
        hasher = ForensicHasher()
        recovered_dir = output_dir / "recovered"
        if recovered_dir.exists():
            hash_results = hasher.hash_directory(str(recovered_dir))
            hasher.write_manifest_csv(hash_results, str(output_dir / "hash_manifest.csv"))
            hasher.write_manifest_json(hash_results, str(output_dir / "hash_manifest.json"))
            console.print(f"  Hashed {len(hash_results)} file(s)")

        # Phase 6: Report
        console.print("[dim]Generating forensic report...[/dim]")
        report = ReportGenerator(case_id=case_id, examiner=examiner)
        report.set_source_info(source, source_hash.size, source_hash.sha256)
        report.set_partition_results(scan_result)
        report.set_recovery_results(recovery_result)
        report.set_timeline_anomalies(anomalies)
        coc_valid, coc_errors = coc.verify_integrity()
        report.set_chain_of_custody_status(coc_valid, coc.entry_count, coc_errors)
        report.generate(str(output_dir / "forensic_report.json"))

        coc.log_action("analysis_completed", {"report": "forensic_report.json"})

        # Phase 7: Evidence bundle (optional)
        if bundle:
            console.print("[dim]Creating evidence bundle...[/dim]")
            latest_session = max(
                (d for d in (output_dir / "recovered").iterdir() if d.is_dir()),
                key=lambda d: d.name,
                default=None,
            )
            if latest_session:
                packager = EvidencePackager(
                    session_dir=str(latest_session),
                    case_id=case_id, examiner=examiner,
                )
                packager.set_recovery_result(recovery_result)
                packager.set_scan_result(scan_result)
                packager.set_timeline(timeline)
                packager.set_chain_of_custody(coc)
                bundle_path = packager.package(
                    str(output_dir / "evidence_bundle"),
                    create_zip=create_zip,
                )
                console.print(f"  Bundle: [green]{bundle_path}[/green]")

        # Summary
        console.print(Panel(
            f"[bold green][OK] Forensic analysis complete[/bold green]\n\n"
            f"[bold]Files recovered:[/bold] {recovery_result.total_files}\n"
            f"[bold]Timeline events:[/bold] {timeline.event_count}\n"
            f"[bold]Anomalies:[/bold] {len(anomalies)}\n"
            f"[bold]CoC entries:[/bold] {coc.entry_count}\n"
            f"[bold]CoC integrity:[/bold] {'PASSED' if coc_valid else 'FAILED'}\n"
            f"[bold]Output:[/bold] {output_dir}",
            title="[bold cyan]Analysis Results[/bold cyan]",
            border_style="green",
        ))

    except (PermissionError, FileNotFoundError) as e:
        coc.log_action("error", {"message": str(e)})
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@cli.command("hash")
@click.argument("target", type=click.Path(exists=True))
@click.option("--output", "-o", default=None, help="Manifest output path")
@click.option("--format", "fmt", type=click.Choice(["csv", "json", "both"]),
              default="both", help="Output format")
def hash_cmd(target: str, output: str | None, fmt: str) -> None:
    """Hash a file or directory with MD5+SHA256."""
    from forensics.hasher import ForensicHasher
    from utils.size_formatter import format_size

    hasher = ForensicHasher()
    target_path = Path(target)

    if target_path.is_file():
        result = hasher.hash_file(str(target_path))
        console.print(Panel(
            f"[bold]File:[/bold] {target}\n"
            f"[bold]Size:[/bold] {format_size(result.size)}\n"
            f"[bold]MD5:[/bold]    {result.md5}\n"
            f"[bold]SHA256:[/bold] {result.sha256}",
            title="[bold cyan]File Hash[/bold cyan]",
            border_style="cyan",
        ))
    elif target_path.is_dir():
        results = hasher.hash_directory(str(target_path))

        table = Table(title="Hash Results", show_header=True, header_style="bold cyan")
        table.add_column("File", style="green")
        table.add_column("Size", justify="right")
        table.add_column("SHA256")

        for r in results[:50]:
            table.add_row(r.path, format_size(r.size), r.sha256[:16] + "...")
        if len(results) > 50:
            table.add_row("...", "...", "...")
        console.print(table)

        if output:
            if fmt in ("csv", "both"):
                hasher.write_manifest_csv(results, output + ".csv" if fmt == "both" else output)
            if fmt in ("json", "both"):
                hasher.write_manifest_json(results, output + ".json" if fmt == "both" else output)
            console.print(f"[green]Manifest written to {output}[/green]")


@cli.command("entropy")
@click.argument("source", type=click.Path(exists=True))
@click.option("--block-size", "-b", default=4096, help="Analysis block size in bytes")
@click.option("--sample", "-s", default=0, help="Sample size (0=full file)")
def entropy_cmd(source: str, block_size: int, sample: int) -> None:
    """Analyze entropy of a file or disk image."""
    from advanced.classifier.entropy import (
        shannon_entropy, classify_entropy, chi_squared_test, monte_carlo_pi_test,
    )
    from advanced.classifier.content_classifier import ContentClassifier
    from utils.size_formatter import format_size

    with open(source, "rb") as f:
        data = f.read(sample if sample > 0 else 1024 * 1024)  # Default 1MB

    e = shannon_entropy(data)
    chi = chi_squared_test(data)
    pi = monte_carlo_pi_test(data)
    classification = classify_entropy(e)

    classifier = ContentClassifier()
    content = classifier.classify(data)

    console.print(Panel(
        f"[bold]File:[/bold] {source}\n"
        f"[bold]Sample:[/bold] {format_size(len(data))}\n\n"
        f"[bold]Shannon Entropy:[/bold] {e:.4f} bits/byte\n"
        f"[bold]Classification:[/bold] {classification}\n"
        f"[bold]Chi-squared:[/bold] {chi:.2f}\n"
        f"[bold]Monte Carlo Pi:[/bold] {pi:.6f} (ideal=3.14159)\n"
        f"[bold]Content Type:[/bold] {content.content_type}\n"
        f"[bold]Confidence:[/bold] {content.confidence:.0%}\n"
        f"[bold]Printable:[/bold] {content.printable_ratio:.1%}\n"
        f"[bold]Null bytes:[/bold] {content.null_ratio:.1%}",
        title="[bold cyan]Entropy Analysis[/bold cyan]",
        border_style="cyan",
    ))


@cli.command("detect-encryption")
@click.argument("source", type=click.Path(exists=True))
def detect_encryption_cmd(source: str) -> None:
    """Scan a disk image for encrypted volumes (LUKS, BitLocker)."""
    from disk.reader import DiskReader
    from advanced.encryption.luks_detector import LUKSDetector
    from advanced.encryption.bitlocker_detector import BitLockerDetector
    from utils.size_formatter import format_size

    console.print(Panel(
        f"[bold]Source:[/bold] {source}\n"
        f"[bold]Scanning for:[/bold] LUKS, BitLocker",
        title="[bold cyan]Encryption Detection[/bold cyan]",
        border_style="cyan",
    ))

    luks_detector = LUKSDetector()
    bl_detector = BitLockerDetector()
    found_any = False

    try:
        with DiskReader(source) as reader:
            console.print("[dim]Scanning for LUKS volumes...[/dim]")
            luks_results = luks_detector.scan_disk(reader)
            for info in luks_results:
                found_any = True
                console.print(Panel(
                    f"[bold red]LUKS{info.version} Detected[/bold red]\n\n"
                    f"[bold]Cipher:[/bold] {info.encryption_description}\n"
                    f"[bold]Hash:[/bold] {info.hash_spec}\n"
                    f"[bold]UUID:[/bold] {info.uuid}\n"
                    f"[bold]Key slots:[/bold] {info.key_slots_active}/{info.key_slots_total}\n"
                    f"[bold]Offset:[/bold] {info.offset}",
                    border_style="red",
                ))

            console.print("[dim]Scanning for BitLocker volumes...[/dim]")
            bl_results = bl_detector.scan_disk(reader)
            for info in bl_results:
                found_any = True
                console.print(Panel(
                    f"[bold red]BitLocker Detected[/bold red]\n\n"
                    f"[bold]Type:[/bold] {info.signature_type}\n"
                    f"[bold]GUID:[/bold] {info.volume_guid}\n"
                    f"[bold]Description:[/bold] {info.description}\n"
                    f"[bold]Offset:[/bold] {info.offset}",
                    border_style="red",
                ))

        if not found_any:
            console.print("[green]No encrypted volumes detected.[/green]")

    except (PermissionError, FileNotFoundError) as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)


@cli.command("preview")
@click.argument("source", type=click.Path(exists=True))
@click.option("--offset", "-o", default=0, help="Start offset in bytes")
@click.option("--length", "-n", default=256, help="Bytes to show")
@click.option("--mode", "-m", type=click.Choice(["hex", "text", "both"]),
              default="hex", help="Preview mode")
def preview_cmd(source: str, offset: int, length: int, mode: str) -> None:
    """Preview file content in hex or text mode."""
    from advanced.classifier.entropy import shannon_entropy, classify_entropy
    from utils.size_formatter import format_size

    with open(source, "rb") as f:
        f.seek(offset)
        data = f.read(length)

    file_size = Path(source).stat().st_size
    entropy = shannon_entropy(data)

    console.print(Panel(
        f"[bold]File:[/bold] {source}\n"
        f"[bold]Size:[/bold] {format_size(file_size)}\n"
        f"[bold]Offset:[/bold] {offset} (0x{offset:X})\n"
        f"[bold]Showing:[/bold] {len(data)} bytes\n"
        f"[bold]Entropy:[/bold] {entropy:.4f} ({classify_entropy(entropy)})",
        title="[bold cyan]File Preview[/bold cyan]",
        border_style="cyan",
    ))

    if mode in ("hex", "both"):
        lines: list[str] = []
        for i in range(0, len(data), 16):
            row = data[i:i + 16]
            addr = f"[dim]{offset + i:08X}[/dim]"
            hex_part = " ".join(f"{b:02X}" for b in row)
            hex_part = hex_part.ljust(48)
            ascii_part = "".join(
                chr(b) if 0x20 <= b <= 0x7e else "." for b in row
            )
            lines.append(f"  {addr}  {hex_part}  [green]|{ascii_part}|[/green]")
        console.print("\n".join(lines))

    if mode in ("text", "both"):
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            text = data.decode("latin-1", errors="replace")
        console.print(Panel(text[:2000], title="Text", border_style="green"))


if __name__ == "__main__":
    # Route to the appropriate interface based on arguments
    if "--ui" in sys.argv:
        # Launch Tkinter GUI
        sys.argv.remove("--ui")
        from ui.app import PyRecoveryApp
        app = PyRecoveryApp()
        app.mainloop()
    elif len(sys.argv) == 1:
        # No arguments → launch interactive wizard
        from cli.wizard import RecoveryWizard
        wizard = RecoveryWizard()
        wizard.run()
    else:
        # Subcommand provided → use existing Click CLI
        cli()
