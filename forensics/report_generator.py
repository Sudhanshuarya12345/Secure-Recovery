"""
pyrecovery.forensics.report_generator — Forensic recovery report generation.

Generates a structured JSON report containing:
- Session metadata (examiner, case info, timestamps)
- Source device/image information
- Partition analysis results
- File recovery summary
- Hash manifest reference
- Timeline anomalies
- Chain of custody verification status
"""

from __future__ import annotations

import json
import platform
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Any

from utils.logger import get_logger

logger = get_logger(__name__)


class ReportGenerator:
    """Generate forensic recovery reports.

    Usage::

        gen = ReportGenerator(
            case_id="2024-001",
            examiner="J. Smith",
        )
        gen.set_source_info(source="evidence.img", size=1073741824)
        gen.set_partition_results(scan_result)
        gen.set_recovery_results(recovery_result)
        gen.set_timeline_anomalies(anomalies)
        gen.generate("output/report.json")
    """

    def __init__(
        self,
        case_id: str = "",
        examiner: str = "",
        notes: str = "",
    ) -> None:
        self._case_id = case_id
        self._examiner = examiner
        self._notes = notes
        self._start_time = datetime.now(timezone.utc)
        self._report_data: dict[str, Any] = {}

    def set_source_info(
        self,
        source: str,
        size: int = 0,
        sha256: str = "",
        device_model: str = "",
    ) -> None:
        """Set information about the source device or image."""
        self._report_data["source"] = {
            "path": source,
            "size_bytes": size,
            "sha256": sha256,
            "device_model": device_model,
        }

    def set_partition_results(self, scan_result) -> None:
        """Set partition scan results."""
        partitions = []
        if hasattr(scan_result, "partitions"):
            for p in scan_result.partitions:
                partitions.append({
                    "index": p.index,
                    "scheme": p.scheme,
                    "type": p.type_name,
                    "filesystem": p.fs_type,
                    "label": p.label,
                    "lba_start": p.lba_start,
                    "lba_end": p.lba_end,
                    "size_bytes": p.size_bytes,
                    "bootable": p.bootable,
                })

        self._report_data["partitions"] = {
            "scheme": getattr(scan_result, "scheme", "unknown"),
            "count": len(partitions),
            "entries": partitions,
            "unallocated_regions": getattr(scan_result, "unallocated", []),
        }

    def set_recovery_results(self, recovery_result) -> None:
        """Set file recovery results."""
        files = []
        if hasattr(recovery_result, "recovered_files"):
            for f in recovery_result.recovered_files:
                files.append({
                    "path": f.path,
                    "size": f.size,
                    "sha256": f.sha256,
                    "source": f.source,
                    "is_deleted": f.is_deleted,
                    "output_path": f.output_path,
                })

        self._report_data["recovery"] = {
            "total_files": getattr(recovery_result, "total_files", 0),
            "from_filesystem": getattr(recovery_result, "files_from_filesystem", 0),
            "from_carving": getattr(recovery_result, "files_from_carving", 0),
            "duration_seconds": getattr(recovery_result, "duration_seconds", 0),
            "files": files,
        }

    def set_timeline_anomalies(self, anomalies: list) -> None:
        """Set timeline analysis anomalies."""
        entries = []
        for a in anomalies:
            entries.append({
                "type": a.anomaly_type,
                "severity": a.severity,
                "description": a.description,
                "event_count": len(a.events),
            })

        self._report_data["timeline_anomalies"] = {
            "count": len(anomalies),
            "anomalies": entries,
        }

    def set_chain_of_custody_status(
        self, is_valid: bool, entry_count: int, errors: list[str]
    ) -> None:
        """Set chain of custody verification status."""
        self._report_data["chain_of_custody"] = {
            "verified": is_valid,
            "entry_count": entry_count,
            "errors": errors[:10],  # Cap for readability
        }

    def set_hash_manifest_path(self, path: str) -> None:
        """Set path to the hash manifest file."""
        self._report_data["hash_manifest"] = path

    def generate(self, output_path: str) -> str:
        """Generate the final forensic report as JSON.

        Args:
            output_path: Path to write the report JSON.

        Returns:
            Path to the generated report file.
        """
        end_time = datetime.now(timezone.utc)

        report = {
            "report_version": "1.0",
            "tool": {
                "name": "PyRecovery",
                "version": "1.0.0",
                "platform": platform.platform(),
                "python_version": platform.python_version(),
            },
            "case": {
                "case_id": self._case_id,
                "examiner": self._examiner,
                "notes": self._notes,
                "start_time": self._start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "duration_seconds": round(
                    (end_time - self._start_time).total_seconds(), 2
                ),
            },
            **self._report_data,
        }

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        logger.info("Forensic report generated: %s", output_path)
        return output_path
