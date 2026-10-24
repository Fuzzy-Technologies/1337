# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit source-only native crawl enrollment for the shared CLI and foreground shell."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import TextIO

from fuzzy1337.adapters import SerializeContract
from fuzzy1337.evidence import EvidenceError
from fuzzy1337.jobs import JobEvent
from fuzzy1337.nucleiscan import ReadNucleiPolicy
from fuzzy1337.policy import ImpactPolicy


def AddCrawlArguments(parser: argparse.ArgumentParser) -> None:
    """Declare only explicit current owned-loopback selection, policy and finite SAFE limits.

    Args:
        parser: Existing shared product action parser with sanitized argument diagnostics.
    """

    parser.add_argument("path", type=Path)
    parser.add_argument("--seed", required=True)
    parser.add_argument("--selected", action="append", required=True,
                        help="Repeat each exact selected URL in canonical lexical order.")
    parser.add_argument("--scope", required=True)
    parser.add_argument("--owner", required=True)
    parser.add_argument("--policy", type=Path, required=True)
    intent = parser.add_mutually_exclusive_group()
    intent.add_argument("--plan", action="store_true")
    intent.add_argument("--approve-safe-crawl", action="store_true")
    parser.add_argument("--max-pages", type=int, default=16)
    parser.add_argument("--max-depth", type=int, default=4)
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--max-total-body-bytes", type=int, default=262144)
    parser.add_argument("--interval", type=float, default=0.05)
    parser.add_argument("--timeout", type=float, default=30)
    parser.add_argument("--max-body-bytes", type=int, default=16384)
    parser.add_argument("--request-timeout-ms", type=int, default=3000)
    parser.add_argument("--events-json", action="store_true")


def RunCrawlCommand(args: argparse.Namespace, output: TextIO, *, json_output: bool) -> int:
    """Use the public SDK without deriving authority from a link or any shell context.

    Args:
        args: Exact parsed crawl action with original selected URL spellings preserved.
        output: Existing safe presentation stream, never raw worker stdout.
        json_output: Select one schema-versioned summary; separate events use JSON lines.

    Returns:
        Actual SDK exit status; two for invalid inputs, three for denial or four for storage.
    """

    from fuzzy1337.native_crawl import NativeCrawlLimits
    from fuzzy1337.native_crawl_workflow import PlanNativeCrawl, RunNativeCrawl
    from fuzzy1337.scan_commands import WriteJson

    try:
        limits = NativeCrawlLimits(args.max_pages, args.max_depth, args.concurrency,
            args.max_total_body_bytes, args.interval, args.timeout, args.max_body_bytes,
            args.request_timeout_ms)

        def Policy() -> ImpactPolicy:
            """Read the exact selected strict policy afresh for each actual authority boundary.

            Returns:
                Current typed operator acquisition policy; approval never manufactures it.
            """

            return ReadNucleiPolicy(args.policy)

        if args.plan:
            document = PlanNativeCrawl(args.path, args.scope, args.seed, tuple(args.selected),
                args.owner, Policy, limits=limits).ToDict()
            WriteJson(output, document)

            return 0

        def OnEvent(event: JobEvent) -> None:
            """Publish only original safe job events, without transient markup or rejected hrefs.

            Args:
                event: Original ordered event retained by the actual outer ScanJob.
            """

            if args.events_json:
                WriteJson(output, {"schema_version": 1, "type": "event",
                                   "event": json.loads(SerializeContract(event))})

        summary = asyncio.run(RunNativeCrawl(args.path, args.scope, args.seed, tuple(args.selected),
            args.owner, Policy, limits=limits, approve_safe_crawl=args.approve_safe_crawl,
            on_event=OnEvent))
        document = summary.ToDict()

        if args.events_json:
            WriteJson(output, {"schema_version": 1, "type": "summary", "summary": document})

        elif json_output:
            WriteJson(output, document)

        else:
            output.write(f"Native crawl {summary.snapshot.state.value}; "
                         f"committed pages {len(summary.completed_urls)}; "
                         f"model revision {summary.model_revision}; "
                         f"workspace revision {summary.workspace_revision}\n")
            output.flush()

        return summary.ExitCode()

    except PermissionError:
        code, status = "authorization", 3

    except (EvidenceError, OSError, RuntimeError):
        code, status = "storage", 4

    except ValueError:
        code, status = "invalid_configuration", 2

    WriteJson(output, {"schema_version": 1, "state": "failed",
        "failure": {"code": code, "message": "Native crawl command could not complete"}})

    return status
