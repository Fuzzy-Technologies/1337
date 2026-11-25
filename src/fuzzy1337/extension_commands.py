# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal offline manifest schema validation and explicit data-only version profiles."""

from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import stat
from collections.abc import Sequence
from importlib.metadata import PackageNotFoundError, distribution
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Never, TextIO, cast

MAX_MANIFEST_BYTES = 64 * 1024
MAX_MANIFEST_NODES = 4096
MAX_MANIFEST_DEPTH = 32
MAX_DIAGNOSTICS = 64
SCHEMA_RESOURCE = "fuzzy1337/contracts/extension-manifest.schema.json"
SEMVER_VERSION_PROFILE = "semver-2.0.0"


class ManifestFailure(ValueError):
    """Retain a fixed operational failure code without source values or filenames."""


class ManifestParser(argparse.ArgumentParser):
    """Keep malformed command values out of argparse diagnostics."""

    def Error(self, message: str) -> Never:
        """Reject grammar through a fixed diagnostic without echoing rejected arguments.

        Args:
            message: Unretained framework diagnostic.

        Returns:
            Never returns because invalid grammar raises a fixed operational failure.
        """

        raise ManifestFailure("configuration")

    error = Error


def UniqueFields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Decode an unambiguous JSON object without silently replacing duplicate members.

    Args:
        pairs: Original object members in their source order.

    Returns:
        Detached unique-key object.
    """

    result: dict[str, object] = {}

    for key, value in pairs:
        if key in result:
            raise ManifestFailure("input-json")

        result[key] = value

    return result


def RejectConstant(value: str) -> object:
    """Refuse non-JSON numeric constants before structural schema validation.

    Args:
        value: Unretained parser token.

    Returns:
        Never returns because the token is outside the admitted JSON input profile.
    """

    raise ManifestFailure("input-json")


def DecodeManifest(payload: bytes) -> object:
    """Admit bounded UTF-8 JSON without changing the Stable schema's structural rules.

    Args:
        payload: Complete original local manifest bytes.

    Returns:
        JSON instance within the independent consumer byte, node and depth limits.
    """

    if not 0 < len(payload) <= MAX_MANIFEST_BYTES:
        raise ManifestFailure("input-limit")

    try:
        instance: object = json.loads(payload.decode("utf-8"), object_pairs_hook=UniqueFields,
                                      parse_constant=RejectConstant)

    except (UnicodeError, json.JSONDecodeError) as error:
        raise ManifestFailure("input-json") from error

    except ManifestFailure:
        raise

    except (ValueError, RecursionError) as error:
        raise ManifestFailure("input-limit") from error

    stack = [(instance, 0)]
    count = 0

    while stack:
        value, depth = stack.pop()
        count += 1

        if count > MAX_MANIFEST_NODES or depth > MAX_MANIFEST_DEPTH:
            raise ManifestFailure("input-limit")

        if isinstance(value, dict):
            stack.extend((child, depth + 1) for child in value.values())

        elif isinstance(value, list):
            stack.extend((child, depth + 1) for child in value)

        elif isinstance(value, float) and not math.isfinite(value):
            raise ManifestFailure("input-limit")

    return instance


def ReadManifest(path: Path) -> bytes:
    """Read one explicit regular input with a bounded overflow byte and no state mutation.

    Args:
        path: Operator-selected local manifest; its contents never select another resource.

    Returns:
        At most the admitted byte ceiling plus one original overflow byte.
    """

    if not stat.S_ISREG(path.stat().st_mode):
        raise ManifestFailure("input-file")

    with path.open("rb") as stream:
        return stream.read(MAX_MANIFEST_BYTES + 1)


def ReadSchema() -> bytes:
    """Read the sole canonical schema from the installed distribution, never the input locator.

    Returns:
        Original bounded schema bytes supplied by the wheel's force-include mapping.
    """

    resource = cast(Traversable, distribution("1337").locate_file(SCHEMA_RESOURCE))

    with resource.open("rb") as stream:
        payload = stream.read(MAX_MANIFEST_BYTES + 1)

    if not 0 < len(payload) <= MAX_MANIFEST_BYTES:
        raise ManifestFailure("schema-unavailable")

    return payload


def StructuralDiagnostics(instance: object, schema: object) -> tuple[list[dict[str, str]], bool]:
    """Use the actual Draft 2020-12 validator with no external reference retrieval.

    Args:
        instance: Already bounded JSON instance; its schema-like members are inert data.
        schema: Trusted installed canonical v1 schema, never supplied by the caller.

    Returns:
        Bounded keyword/JSON-pointer diagnostics and explicit truncation state.
    """

    try:
        from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
        from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]
        from referencing import Registry
        from referencing.exceptions import Unresolvable

    except ImportError as error:
        raise ManifestFailure("validator-unavailable") from error

    try:
        # Registry has no retrieval callback: only this schema's in-memory fragment refs resolve.
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, registry=Registry())
        errors = list(itertools.islice(validator.iter_errors(instance), MAX_DIAGNOSTICS + 1))

    except (SchemaError, Unresolvable) as error:
        raise ManifestFailure("schema-unavailable") from error

    diagnostics = []

    for issue in errors[:MAX_DIAGNOSTICS]:
        path = "".join("/" + str(part).replace("~", "~0").replace("/", "~1")
                       for part in issue.absolute_path)
        diagnostics.append({"code": str(issue.validator), "path": path})

    return diagnostics, len(errors) > MAX_DIAGNOSTICS


def IsSemVer200(value: object) -> bool:
    """Check the ASCII SemVer 2.0.0 version-string grammar without resolution or ordering.

    Args:
        value: Declared extension version; this function neither coerces nor rewrites metadata.

    Returns:
        True for the version-string grammar in specification sections 2, 9 and 10.
        Numeric components remain strings, with no integer conversion or additional digit limit.
    """

    if type(value) is not str or not value.isascii():
        return False

    version, hasBuild, build = value.partition("+")
    core, hasPrerelease, prerelease = version.partition("-")
    numbers = core.split(".")

    if len(numbers) != 3 or any(
        not part.isdigit() or (len(part) > 1 and part.startswith("0")) for part in numbers
    ):
        return False

    for suffix, present, allowLeadingZeros in (
        (prerelease, hasPrerelease, False), (build, hasBuild, True),
    ):
        if not present:
            continue

        for identifier in suffix.split("."):
            if not identifier or any(
                not (character.isalnum() or character == "-") for character in identifier
            ):
                return False

            if not allowLeadingZeros and identifier.isdigit() and (
                len(identifier) > 1 and identifier.startswith("0")
            ):
                return False

    return True


def RunExtensionCommands(
    arguments: Sequence[str], output: TextIO, *, jsonOutput: bool = False,
) -> int:
    """Validate one explicit manifest locally without interpreting compatibility or activating it.

    Args:
        arguments: Validate action, local filename and optional version profile, or action help.
        output: Caller-owned terminal stream.
        jsonOutput: Emit profile-one fixed diagnostics with any explicitly selected version profile.

    Returns:
        Zero for accepted metadata, one for invalid metadata, two for input/setup refusal,
        four for unavailable packaged schema, or 130 for interruption.
    """

    parser = ManifestParser(prog="1337 extension", add_help=False, allow_abbrev=False)
    actions = parser.add_subparsers(dest="action", required=True, parser_class=ManifestParser)
    validate = actions.add_parser("validate", add_help=False, allow_abbrev=False)
    validate.add_argument("manifest", type=Path)
    validate.add_argument("--version-profile", choices=(SEMVER_VERSION_PROFILE,))

    if list(arguments) in (["--help"], ["-h"], ["validate", "--help"], ["validate", "-h"]):
        validate.print_help(file=output)

        return 0

    outcome: dict[str, object] = {
        "schema_version": 1, "command": "extension.validate", "status": "failed",
        "failure": None, "manifest_sha256": None, "schema_sha256": None,
        "contract_schema_version": 1, "diagnostics": [], "diagnostics_truncated": False,
        "core_compatibility": "not-evaluated", "extension_activation": "not-attempted",
    }
    status = 2
    phase = "configuration"
    diagnostics: list[dict[str, str]] = []

    try:
        options = parser.parse_args(arguments)

        if options.version_profile is not None:
            outcome["version_profile"] = options.version_profile

        phase = "input-file"
        raw = ReadManifest(options.manifest)
        phase = "input-json"
        instance = DecodeManifest(raw)
        outcome["manifest_sha256"] = hashlib.sha256(raw).hexdigest()
        phase = "schema-unavailable"
        schemaRaw = ReadSchema()
        schema = json.loads(schemaRaw)
        outcome["schema_sha256"] = hashlib.sha256(schemaRaw).hexdigest()
        diagnostics, truncated = StructuralDiagnostics(instance, schema)

        if options.version_profile == SEMVER_VERSION_PROFILE and not diagnostics:
            extension = instance.get("extension") if isinstance(instance, dict) else None
            version = extension.get("version") if isinstance(extension, dict) else None

            if not IsSemVer200(version):
                diagnostics = [{"code": SEMVER_VERSION_PROFILE, "path": "/extension/version"}]

        outcome.update(status="invalid" if diagnostics else "valid", diagnostics=diagnostics,
                       diagnostics_truncated=truncated)
        status = 1 if diagnostics else 0

    except ManifestFailure as error:
        outcome["failure"] = str(error)
        status = 4 if str(error) == "schema-unavailable" else 2

    except (OSError, PackageNotFoundError, ValueError, RecursionError):
        outcome["failure"] = phase
        status = 4 if phase == "schema-unavailable" else 2

    except KeyboardInterrupt:
        outcome["failure"] = "interrupted"
        status = 130

    if jsonOutput:
        output.write(json.dumps(outcome, sort_keys=True, ensure_ascii=True) + "\n")

    else:
        output.write(f"extension.validate: {outcome['status']}\n")

        if "version_profile" in outcome:
            output.write(f"Version profile: {outcome['version_profile']}\n")

        for item in diagnostics:
            output.write(f"{item['code']}: {json.dumps(item['path'], ensure_ascii=True)}\n")

        if outcome["diagnostics_truncated"]:
            output.write("diagnostics-truncated\n")

        if outcome["failure"] is not None:
            output.write(f"failure: {outcome['failure']}\n")

        if outcome["failure"] == "validator-unavailable":
            output.write("Install the optional 1337[validate] extra before validating manifests.\n")

        output.write("Core compatibility: not evaluated; extension activation: not attempted.\n")

    return status
