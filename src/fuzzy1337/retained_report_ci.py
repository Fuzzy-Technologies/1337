# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal CI bundle publication through existing offline report CLI contracts."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import re
import stat
import sys
import tempfile
from pathlib import Path
from typing import cast

MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_JUNIT_BYTES = 30_000_000
RECEIPT_FIELDS = frozenset({
    "schema_version", "command", "status", "format", "model_revision", "snapshot_sha256",
    "report_sha256", "size_bytes", "output_published", "scan_completeness",
    "verified_retained_acquisitions", "checked_model_evidence_references", "failure",
})


def VerifyReport(path: Path, outcome: dict[str, object]) -> None:
    """Verify acknowledged bounded regular-file bytes before bundle publication.

    Args:
        path: Staged report selected by the existing offline CLI.
        outcome: Original parsed export receipt with its length and SHA-256.

    Raises:
        OSError: The selected staged file cannot be inspected or read.
        ValueError: File type, acknowledged length or original digest does not match.
    """

    metadata = path.lstat()
    size = outcome.get("size_bytes")
    digest = outcome.get("report_sha256")

    if (type(size) is not int or not 0 <= size <= MAX_REPORT_BYTES
            or not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)
            or not stat.S_ISREG(metadata.st_mode) or metadata.st_size != size):
        raise ValueError("The offline CLI did not acknowledge the selected report bytes.")

    with path.open("rb") as stream:
        payload = stream.read(MAX_REPORT_BYTES + 1)

    if len(payload) != size or hashlib.sha256(payload).hexdigest() != digest:
        raise ValueError("The staged report no longer matches its original export receipt.")


def ExportReceipt(receipt: str, formatName: str, destination: Path) -> dict[str, object]:
    """Check an original successful CLI receipt without inventing a new result schema.

    Args:
        receipt: Original JSON stdout of the installed report export entry point.
        formatName: Explicit existing report format selected by this invocation.
        destination: New staged output acknowledged by the selected command.

    Returns:
        Successful existing version-one receipt after identity and file verification.

    Raises:
        OSError: The staged report cannot be verified.
        ValueError: Receipt JSON, completion, identity or acknowledged bytes are invalid.
    """

    outcome = json.loads(receipt)

    if (not isinstance(outcome, dict) or set(outcome) != RECEIPT_FIELDS
            or outcome.get("command") != "report.export"
            or outcome.get("schema_version") != 1 or outcome.get("status") != "completed"
            or outcome.get("output_published") is not True or outcome.get("format") != formatName
            or outcome.get("failure") is not None
            or outcome.get("scan_completeness") != "not-assessed"):
        raise ValueError("The offline CLI did not acknowledge a completed report export.")

    for key in ("schema_version", "model_revision", "verified_retained_acquisitions",
                "checked_model_evidence_references"):
        value = outcome.get(key)

        if type(value) is not int or value < 0:
            raise ValueError("The offline CLI returned invalid snapshot verification metadata.")

    digest = outcome.get("snapshot_sha256")

    if not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("The offline CLI returned invalid snapshot identity.")

    VerifyReport(destination, outcome)

    return cast(dict[str, object], outcome)


def Main(project: Path, namespace: str, sourceInput: str) -> int:
    """Export matched JSON/JUnit and original receipts into one complete CI-owned bundle.

    Args:
        project: Existing caller project directory and actual working directory.
        namespace: Bounded CI-owned filename suffix supplied by the platform bootstrap.
        sourceInput: Explicit saved workspace inside the project, outside reserved output.

    Returns:
        Zero after complete publication, the original CLI failure status, four for bundle
        refusal, or 130 for interruption. Finding dispositions do not change export status.
    """

    try:
        project = project.resolve(strict=True)

        if (not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,159}", namespace)
                or Path.cwd().resolve() != project):
            raise ValueError("Run from the project directory with a valid CI output namespace.")

        bundle = project / f"1337-retained-report-{namespace}"

        if bundle.exists() or bundle.is_symlink():
            retired = Path(tempfile.mkdtemp(prefix=".1337-retired-", dir=project))
            bundle.rename(retired / "bundle")

        source = (project / sourceInput).resolve() if sourceInput else None

        if source is None or not source.is_relative_to(project):
            raise ValueError("Select a saved workspace inside the project.")

        if (source == project or source.is_relative_to(bundle)
                or bundle.is_relative_to(source)):
            raise ValueError("The report output namespace cannot contain the saved workspace.")

        from fuzzy1337.cli import Main as RunCli

        with tempfile.TemporaryDirectory(prefix=".1337-report-", dir=project) as temporary:
            staging = Path(temporary) / "bundle"
            staging.mkdir()
            reports = []

            for formatName, filename in (("json", "report.json"), ("junit", "report.junit.xml")):
                output = io.StringIO()
                destination = staging / filename

                with contextlib.redirect_stdout(output):
                    status = RunCli(["report", "export", str(source), "--format", formatName,
                                     "--output", str(destination), "--json"])

                receipt = output.getvalue()
                print(receipt, end="")

                if status != 0:
                    return status

                outcome = ExportReceipt(receipt, formatName, destination)

                with (staging / f"{formatName}-export.json").open(
                    "x", encoding="utf-8", newline="",
                ) as stream:
                    stream.write(receipt)

                reports.append((formatName, destination, outcome, receipt))

            identity = ("model_revision", "snapshot_sha256", "verified_retained_acquisitions",
                        "checked_model_evidence_references")

            if any(reports[0][2][key] != reports[1][2][key] for key in identity):
                raise ValueError("The saved workspace changed between offline exports.")

            # Recheck both original receipts and report bytes after both commands;
            # publication must not admit an earlier output altered during the second export.
            for formatName, destination, outcome, receipt in reports:
                VerifyReport(destination, outcome)

                receiptBytes = receipt.encode("utf-8")
                VerifyReport(staging / f"{formatName}-export.json", {
                    "size_bytes": len(receiptBytes),
                    "report_sha256": hashlib.sha256(receiptBytes).hexdigest(),
                })

            if (staging / "report.junit.xml").stat().st_size >= MAX_JUNIT_BYTES:
                raise ValueError("The JUnit projection exceeds the shared GitLab report limit.")

            staging.rename(bundle)

    except (ImportError, KeyError, OSError, ValueError) as error:
        print(f"Retained report bundle refused: {error}", file=sys.stderr)

        return 4

    except KeyboardInterrupt:
        print("Retained report bundle interrupted before completion.", file=sys.stderr)

        return 130

    return 0
