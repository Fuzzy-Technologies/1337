# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Independent portable image fixture wire checks, without an execution-policy or scan claim."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import tarfile
from io import BytesIO
from pathlib import Path
from threading import Event, Thread

import pytest

FIXTURE_ROOT = Path(__file__).parents[1] / "fixtures" / "image_scan"
ORACLE = json.loads((FIXTURE_ROOT / "oracle.json").read_bytes())
PREFIX = (sys.executable, "-I", "-S", str(FIXTURE_ROOT / "producer.py"))
IMAGE_FLAGS = (
    "--format", "json", "--scanners", "vuln", "--disable-telemetry", "--offline-scan",
    "--skip-db-update", "--skip-java-db-update", "--skip-check-update", "--skip-version-check",
    "--skip-vex-repo-update", "--ignorefile=", "--list-all-pkgs", "--exit-code", "0",
    "--no-progress", "--timeout", "1s",
)


def FixtureModule():
    """Import only the repository-owned deterministic archive builder from its exact path."""

    spec = importlib.util.spec_from_file_location(
        "owned_image_fixture", FIXTURE_ROOT / "fixture_image.py",
    )
    assert spec is not None and spec.loader is not None, "The owned fixture must be importable."
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


def ImageArguments(image: Path, policy: Path) -> tuple[str, ...]:
    """Declare the profile independently of the producer's flag validator."""

    return ("--fixture-policy", str(policy),
            "--cache-dir", str(image.parent.parent / "scratch" / "cache"), "--config=", "image",
            "--cache-backend", "memory", "--input", str(image), *IMAGE_FLAGS)


def Environment() -> dict[str, str]:
    """Pass only Windows' interpreter prerequisite, without user/provider environment overlays."""

    return {"SYSTEMROOT": os.environ["SYSTEMROOT"]} if "SYSTEMROOT" in os.environ else {}


def Run(root: Path, arguments: tuple[str, ...]) -> subprocess.CompletedProcess[bytes]:
    """Run only the bounded owned fixture through a portable isolated interpreter prefix."""

    return subprocess.run((*PREFIX, *arguments), cwd=root / "scratch", env=Environment(),
                          stdin=subprocess.DEVNULL, capture_output=True, timeout=5, check=False)


def test_OwnedArchiveHasIndependentStableContentAndDomainHashes(tmp_path):
    """Do not derive expected identities from the provider's emitted labels or a registry tag."""

    module = FixtureModule()
    image, policy = module.CreateFixture(tmp_path / "owned workspace")
    raw = image.read_bytes()
    assert len(raw) == ORACLE["success_archive"]["size_bytes"], (
        "Archive size changed without review."
    )
    assert hashlib.sha256(raw).hexdigest() == ORACLE["success_archive"]["sha256"], (
        "The committed success archive oracle must pin the independently generated raw bytes."
    )

    with tarfile.open(fileobj=BytesIO(raw), mode="r:") as archive:
        members = {member.name: archive.extractfile(member).read() for member in archive}

    docker = json.loads(members["manifest.json"])[0]
    facts = ORACLE["domain_facts"]
    assert "sha256:" + hashlib.sha256(members[docker["Config"]]).hexdigest() == (
        facts["config_digest"]
    ), "The config identity must hash actual config bytes, not archive bytes."
    assert "sha256:" + hashlib.sha256(members["oci-manifest.json"]).hexdigest() == (
        facts["manifest_digest"]
    ), "Manifest and config identities must retain distinct byte semantics."
    assert "sha256:" + hashlib.sha256(members[docker["Layers"][0]]).hexdigest() == (
        facts["layer_diff_id"]
    ), "The uncompressed layer fixture has a separate independently verified DiffID."
    identities = {facts["config_digest"], facts["manifest_digest"], facts["layer_diff_id"],
                  "sha256:" + ORACLE["success_archive"]["sha256"]}
    assert len(identities) == 4, (
        "Source archive, config, manifest and layer hashes must not collapse."
    )
    native = json.loads(Run(image.parent.parent, ImageArguments(image, policy)).stdout)
    assert native["Metadata"]["ImageID"] == facts["config_digest"], (
        "The synthetic producer must describe the fixture's actual independently pinned config."
    )
    assert native["Metadata"]["RepoDigests"] == [
        "owned.invalid/synthetic@" + facts["manifest_digest"],
    ], (
        "The synthetic manifest association must match the separate manifest oracle."
    )
    assert native["Metadata"]["OS"] == {
        "Family": facts["operating_system"]["family"],
        "Name": facts["operating_system"]["version"],
    }, "Keep synthetic OS claims explicit and separate from inert layer contents."


def test_IndependentNamespaceOracleCoversAllCollidingNativeAssetsAndTriage():
    """Prepare exact future collision assertions without claiming production import execution."""

    facts = ORACLE["domain_facts"]
    prefix = ORACLE["synthetic_asset_prefix"]
    assert prefix == "synthetic.trivy:owned-synthetic-image-wire-v1:", (
        "The reviewed synthetic namespace is fixed, never selected by emitted provider labels."
    )
    baseline = ORACLE["native_namespace_baseline"]
    native_keys = {seed["natural_key"] for seed in baseline["asset_seeds"]}
    synthetic_keys = set(facts["synthetic_asset_keys"].values())
    assert len(native_keys) == len(synthetic_keys) == 6, (
        "Config, manifest, package, OS, layer and license all need collision coverage."
    )
    assert synthetic_keys == {prefix + key for key in native_keys}, (
        "Each colliding native identity must have exactly one separately namespaced fixture key."
    )
    assert synthetic_keys.isdisjoint(native_keys), "No fixture asset may reuse a native key."
    os_bytes = json.dumps({"family": "alpine", "name": "3.20"},
                          sort_keys=True, separators=(",", ":")).encode()
    os_key = "operating-system:" + hashlib.sha256(os_bytes).hexdigest()
    license_key = "license-declaration:" + hashlib.sha256(b"MIT").hexdigest()
    assert prefix + os_key == facts["synthetic_asset_keys"]["operating_system"], (
        "The independent OS oracle must retain the accepted domain hash semantics."
    )
    assert prefix + license_key == facts["synthetic_asset_keys"]["license"], (
        "License identity must describe its exact declared expression, not image or package IDs."
    )
    native_finding = baseline["triaged_finding"]
    synthetic_finding = facts["finding"]
    assert native_finding["subject_object_key"] in native_keys and (
        synthetic_finding["subject_object_key"] == facts["synthetic_asset_keys"]["package"]
    ), "Native and synthetic Findings must retain their respective exact package subjects."
    assert synthetic_finding["check_id"] == "synthetic.supply-chain.vulnerability" and (
        native_finding["check_id"] == "supply-chain.vulnerability"
    ), "Finding fingerprints need distinct checks as well as isolated subject identities."
    assert native_finding["location_key"] == synthetic_finding["location_key"] and (
        native_finding["status"] == "dismissed" and synthetic_finding["status"] == "open"
    ), "The future collision test must cover an already triaged overlapping advisory."


def test_IsolatedPortableVersionWireIsExplicitlySynthetic(tmp_path):
    """No shebang, external executable, DB download or real provider-health assertion is needed."""

    image, policy = FixtureModule().CreateFixture(tmp_path / "version workspace")
    result = Run(image.parent.parent, (
        "--fixture-policy", str(policy),
        "--cache-dir", str(image.parent.parent / "scratch" / "cache"),
        "--config=", "--version", "--format", "json",
    ))
    version = json.loads(result.stdout)
    assert result.returncode == 0, "The pinned isolated interpreter must support the version wire."
    assert version["Version"] == ORACLE["provider_version"], "Keep the synthetic version explicit."
    assert version["VulnerabilityDB"]["Version"] == 2, "The fixture uses schema-v2 DB metadata."
    assert "synthetic" in version["Fixture"], "Do not impersonate actual DB health."


@pytest.mark.parametrize("scenario", ["success", "no_findings", "provider_error",
                                     "version_mismatch", "package_mismatch"])
def test_FiniteWireCasesPreserveIndependentOutcomeOracle(tmp_path, scenario):
    """A complete JSON body on exit seven remains an execution failure for future consumers."""

    image, policy = FixtureModule().CreateFixture(tmp_path / scenario, scenario)
    result = Run(image.parent.parent, ImageArguments(image, policy))
    expected = ORACLE["scenarios"][scenario]
    native = json.loads(result.stdout)
    assert result.returncode == expected["process_exit_code"], "Fixture exit truth changed."
    assert b"no image scan or network" in result.stderr, "Synthetic provenance must remain visible."
    assert native["ArtifactType"] == "container_image" and native["SchemaVersion"] == 2, (
        "The owned wire must exercise the exact accepted image report envelope."
    )
    package = native["Results"][0]["Packages"][0]
    assert package["Identifier"]["PURL"] == ORACLE["domain_facts"]["package"]["purl"], (
        "Installed package-version identity must match the independent oracle."
    )
    assert package["Licenses"] == [ORACLE["domain_facts"]["license"]["expression"]], (
        "Keep the colliding license claim pinned independently of the producer's labels."
    )
    findings = native["Results"][0]["Vulnerabilities"]

    if scenario in {"success", "no_findings"}:
        assert len(findings) == expected["proposed_findings"], "Fixture finding proposals changed."

    if scenario == "version_mismatch":
        assert native["Trivy"]["Version"] != ORACLE["provider_version"], (
            "The version mismatch case must remain contradictory for downstream rejection."
        )

    if scenario == "package_mismatch":
        assert findings[0]["PkgID"] != package["ID"], (
            "The unmatched package case must remain unambiguously rejectable."
        )


@pytest.mark.parametrize(
    "change", ["added_flag", "changed_scanner", "changed_cache", "zero_timeout", "large_timeout"],
)
def test_FixedProfileRejectsFlagAdditionsAndChanges(tmp_path, change):
    """No caller-selected raw flag or profile change can become fixture execution approval."""

    image, policy = FixtureModule().CreateFixture(tmp_path / change)
    arguments = list(ImageArguments(image, policy))

    if change == "added_flag":
        arguments.append("--quiet")

    elif change == "changed_scanner":
        arguments[arguments.index("--scanners") + 1] = "misconfig"

    elif change == "changed_cache":
        arguments[arguments.index("--cache-backend") + 1] = "fs"

    else:
        arguments[-1] = "0s" if change == "zero_timeout" else "61s"

    result = Run(image.parent.parent, tuple(arguments))
    assert result.returncode == 64 and not result.stdout, "Unsupported profile must fail closed."


@pytest.mark.parametrize("change", ["boolean_schema", "floating_db_version", "extra_field",
                                    "duplicate_field", "changed_version"])
def test_SyntheticPolicyHasOneExactNonExecutableInterpretation(tmp_path, change):
    """Pinned data cannot select a scanner profile or silently repair ambiguous metadata."""

    image, policy = FixtureModule().CreateFixture(tmp_path / change)
    metadata = json.loads(policy.read_bytes())

    if change == "boolean_schema":
        metadata["schema_version"] = True

    elif change == "floating_db_version":
        metadata["database_metadata"]["Version"] = 2.0

    elif change == "extra_field":
        metadata["arguments"] = ["--quiet"]

    elif change == "changed_version":
        metadata["provider_version"] = "0.75.1-synthetic"

    raw = json.dumps(metadata).encode()

    if change == "duplicate_field":
        raw = b'{"schema_version":1,' + raw[1:]

    policy.write_bytes(raw)
    result = Run(image.parent.parent, ImageArguments(image, policy))
    assert result.returncode == 64 and not result.stdout, (
        "The fixed synthetic policy must reject unknown, ambiguous or mistyped data."
    )


@pytest.mark.parametrize("change", ["oversized", "unlisted_member", "duplicate_scenario"])
def test_ArchiveReadBoundsAndClosedMembersNeverExtractFiles(tmp_path, change):
    """Hostile archive structure is data and cannot write an unlisted path or select code."""

    module = FixtureModule()
    image, policy = module.CreateFixture(tmp_path / change)

    if change == "oversized":
        raw = b"X" * (128 * 1024 + 1)

    elif change == "unlisted_member":
        raw = module.TarBytes((("../unlisted.txt", b"owned inert rejection marker"),))

    else:
        with tarfile.open(fileobj=BytesIO(image.read_bytes()), mode="r:") as archive:
            members = [(member.name, archive.extractfile(member).read()) for member in archive]

        raw = module.TarBytes(tuple(
            (name, b'{"scenario":"hold","scenario":"success"}'
             if name == "1337-fixture.json" else data)
            for name, data in members
        ))

    image.write_bytes(raw)
    result = Run(image.parent.parent, ImageArguments(image, policy))
    assert result.returncode == 64 and not result.stdout, "The archive specimen must fail closed."
    assert image.read_bytes() == raw, "Rejected input bytes must stay untouched."
    assert not (image.parent.parent / "unlisted.txt").exists(), (
        "No archive member may become a filesystem write."
    )


def test_MalformedAndOverflowWireRemainBoundedFailureSpecimens(tmp_path):
    """Keep exact hostile output specimens without calling them normalized scan results."""

    module = FixtureModule()
    image, policy = module.CreateFixture(tmp_path / "malformed", "malformed")
    result = Run(image.parent.parent, ImageArguments(image, policy))

    with pytest.raises(json.JSONDecodeError):
        json.loads(result.stdout)

    assert result.stdout == b'{"SchemaVersion":2', "Malformed raw bytes must remain reproducible."
    image, policy = module.CreateFixture(tmp_path / "overflow", "output_limit")
    result = Run(image.parent.parent, ImageArguments(image, policy))
    assert len(result.stdout) == ORACLE["scenarios"]["output_limit"]["stdout_size_bytes"], (
        "The producer must cross the accepted stdout bound by exactly one detection byte."
    )


def test_HoldSpecimenStartsPortablyAndItsOwnerReapsTheProcess(tmp_path):
    """Prepare genuine process ownership for later timeout/cancellation executor assertions."""

    image, policy = FixtureModule().CreateFixture(tmp_path / "hold", "hold")
    process = subprocess.Popen((*PREFIX, *ImageArguments(image, policy)),
                               cwd=image.parent.parent / "scratch",
                               env=Environment(), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ready = Event()
    startup: list[bytes] = []

    def ObserveStartup() -> None:
        """Bound readiness by actual owned producer output instead of a cold-start sleep."""

        assert process.stderr is not None, "The fixture must own its stderr readiness pipe."
        startup.append(process.stderr.readline())
        ready.set()

    observer = Thread(target=ObserveStartup, daemon=True)
    observer.start()

    try:
        assert ready.wait(5), "The synthetic producer must announce readiness within its budget."
        observer.join(timeout=1)
        assert b"no image scan or network" in startup[0], "The held producer must actually start."

        with pytest.raises(subprocess.TimeoutExpired):
            process.communicate(timeout=0.1)

    finally:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)
        observer.join(timeout=1)

    assert stdout == ORACLE["scenarios"]["hold"]["partial_stdout"].encode(), (
        "The held process must retain the exact incomplete raw prefix before cleanup."
    )
    assert not stderr, "The fixed held profile must not produce extra unbounded diagnostics."
    assert not observer.is_alive(), "The fixture owner must join the readiness observer."
    assert process.poll() is not None, "The fixture owner must reap its actual subprocess."
