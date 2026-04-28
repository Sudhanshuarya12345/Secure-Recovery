"""
pyrecovery.forensics.evidence_packager — Package recovery output as a forensic evidence bundle.

Creates a self-contained directory (or ZIP) containing:
- All recovered files (organized by source/category)
- Hash manifest (CSV and JSON)
- Chain of custody log
- Forensic timeline (CSV and JSON)
- Recovery report (JSON)
- README with package structure documentation

This bundle is the final deliverable for court or client handoff.
"""

from __future__ import annotations

import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from forensics.hasher import ForensicHasher
from forensics.chain_of_custody import ChainOfCustody
from forensics.timeline import ForensicTimeline
from forensics.report_generator import ReportGenerator
from utils.logger import get_logger

logger = get_logger(__name__)


class EvidencePackager:
    """Package all forensic output into a court-ready evidence bundle.

    Usage::

        packager = EvidencePackager(
            session_dir="./recovered/20240101_120000",
            case_id="2024-001",
            examiner="J. Smith",
        )
        packager.set_recovery_result(result)
        packager.set_timeline(timeline)
        packager.set_chain_of_custody(coc)
        bundle_path = packager.package(output_path="./evidence_bundle")
    """

    def __init__(
        self,
        session_dir: str,
        case_id: str = "",
        examiner: str = "",
    ) -> None:
        self._session_dir = Path(session_dir)
        self._case_id = case_id
        self._examiner = examiner
        self._recovery_result = None
        self._timeline: ForensicTimeline | None = None
        self._coc: ChainOfCustody | None = None
        self._scan_result = None

    def set_recovery_result(self, result) -> None:
        self._recovery_result = result

    def set_scan_result(self, result) -> None:
        self._scan_result = result

    def set_timeline(self, timeline: ForensicTimeline) -> None:
        self._timeline = timeline

    def set_chain_of_custody(self, coc: ChainOfCustody) -> None:
        self._coc = coc

    def package(
        self,
        output_path: str | None = None,
        create_zip: bool = False,
    ) -> str:
        """Create the evidence bundle.

        Args:
            output_path: Destination for the bundle directory.
                         If None, creates in session_dir parent.
            create_zip: Also create a ZIP archive of the bundle.

        Returns:
            Path to the evidence bundle directory.
        """
        if output_path is None:
            output_path = str(
                self._session_dir.parent / f"evidence_bundle_{self._case_id or 'session'}"
            )

        bundle_dir = Path(output_path)
        bundle_dir.mkdir(parents=True, exist_ok=True)

        # 1. Copy recovered files
        files_dir = bundle_dir / "recovered_files"
        if self._session_dir.exists():
            if files_dir.exists():
                shutil.rmtree(files_dir)
            shutil.copytree(self._session_dir, files_dir, dirs_exist_ok=True)
            logger.info("Copied recovered files to bundle")

        # 2. Generate hash manifest
        hasher = ForensicHasher()
        if files_dir.exists():
            hashes = hasher.hash_directory(str(files_dir))
            hasher.write_manifest_csv(
                hashes, str(bundle_dir / "hash_manifest.csv")
            )
            hasher.write_manifest_json(
                hashes, str(bundle_dir / "hash_manifest.json")
            )

        # 3. Export timeline
        if self._timeline:
            self._timeline.export_csv(str(bundle_dir / "timeline.csv"))
            self._timeline.export_json(str(bundle_dir / "timeline.json"))

            anomalies = self._timeline.detect_anomalies()
            if anomalies:
                anomaly_data = [
                    {
                        "type": a.anomaly_type,
                        "severity": a.severity,
                        "description": a.description,
                    }
                    for a in anomalies
                ]
                with open(bundle_dir / "timeline_anomalies.json", "w", encoding="utf-8") as f:
                    json.dump(anomaly_data, f, indent=2)

        # 4. Copy chain of custody log
        if self._coc and Path(self._coc.log_path).exists():
            shutil.copy2(self._coc.log_path, bundle_dir / "chain_of_custody.jsonl")
            valid, errors = self._coc.verify_integrity()
            with open(bundle_dir / "coc_verification.json", "w", encoding="utf-8") as f:
                json.dump({"valid": valid, "errors": errors}, f, indent=2)

        # 5. Generate forensic report
        report = ReportGenerator(
            case_id=self._case_id, examiner=self._examiner,
        )
        if self._recovery_result:
            report.set_recovery_results(self._recovery_result)
        if self._scan_result:
            report.set_partition_results(self._scan_result)
        if self._timeline:
            report.set_timeline_anomalies(self._timeline.detect_anomalies())
        if self._coc:
            valid, errors = self._coc.verify_integrity()
            report.set_chain_of_custody_status(valid, self._coc.entry_count, errors)
        report.set_hash_manifest_path("hash_manifest.csv")
        report.generate(str(bundle_dir / "forensic_report.json"))

        # 6. Generate README
        self._write_readme(bundle_dir)

        # 7. Optional ZIP
        if create_zip:
            zip_path = str(bundle_dir) + ".zip"
            with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for file in bundle_dir.rglob("*"):
                    if file.is_file():
                        zf.write(file, file.relative_to(bundle_dir))
            logger.info("Evidence bundle ZIP created: %s", zip_path)

        logger.info("Evidence bundle created: %s", bundle_dir)
        return str(bundle_dir)

    def _write_readme(self, bundle_dir: Path) -> None:
        """Write a README documenting the bundle structure."""
        readme = f"""# Forensic Evidence Bundle
# Generated by PyRecovery v1.0.0
# {datetime.now(timezone.utc).isoformat()}

## Case Information
- Case ID: {self._case_id or 'N/A'}
- Examiner: {self._examiner or 'N/A'}

## Bundle Contents

### recovered_files/
All files recovered during this session, organized by source
(partition, carved) and type.

### hash_manifest.csv / hash_manifest.json
Dual MD5+SHA256 hashes of every recovered file.
Use to verify file integrity at any later point.

### chain_of_custody.jsonl
Append-only, tamper-evident log of all actions performed.
Each entry contains a SHA256 hash chain linking to the previous entry.

### coc_verification.json
Result of chain-of-custody integrity verification.

### timeline.csv / timeline.json
Chronological timeline of all filesystem events
(create, modify, access, delete) from recovered files.

### timeline_anomalies.json
Detected anomalies: future timestamps, impossible sequences,
pre-epoch dates, suspicious clustering.

### forensic_report.json
Comprehensive session report including partition analysis,
recovery statistics, and tool information.

## Verification

To verify file integrity:
1. Compare hash_manifest.csv against recovered_files/
2. Verify chain_of_custody.jsonl hash chain integrity
3. Cross-reference forensic_report.json timestamps

## Legal Notice

This evidence bundle was generated by automated forensic tools.
All recovered files are exact byte-for-byte copies of data found
on the source media. No data was modified, added, or removed from
the source during the recovery process.
"""
        with open(bundle_dir / "README.txt", "w", encoding="utf-8") as f:
            f.write(readme)
