# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Protect immutable-manifest passive routing against false scope claims."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from tools import passive_scope as policy

BASE = "a" * 40
POLICY = "f" * 40
HEAD = "feature/passive-batch-workbench"
ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = {
    "nmap-acceptance.yml": "owned-loopback", "nuclei-acceptance.yml": "owned-loopback",
    "trivy-acceptance.yml": "owned-offline", "local-image-product.yml": "owned-local-image",
    "native-configuration-material.yml": "installed-read-helper",
    "native-configuration-product.yml": "installed-native-configuration",
    "owned-gitlab-acceptance.yml": "owned-gitlab", "zap-inert-acceptance.yml": "closed-inert",
    "owned-content-header-acceptance.yml": "installed-content-header",
}
OPTIONAL_VETO = (
    "!(github.event_name == 'pull_request' && github.base_ref == 'develop' "
    "&& startsWith(github.head_ref, 'feature/passive-batch-')) && ("
)


def Change(path="CHANGELOG.md", status="M"):
    """Build exact synthetic raw Git metadata without invoking a product or scanner."""

    oldMode, newMode, oldHash, newHash = "100644", "100644", "b" * 40, "c" * 40

    if status == "A":
        oldMode, oldHash = "000000", "0" * 40

    elif status == "D":
        newMode, newHash = "000000", "0" * 40

    return f":{oldMode} {newMode} {oldHash} {newHash} {status}\0{path}\0".encode()


def Manifest(payload):
    """Represent a separately reviewed exact diff rather than a head-supplied skip request."""

    return {"schema_version": 1, "base_commit": BASE, "head_ref": HEAD,
            "changes": policy.Changes(payload)}


def Classify(payload, manifest=None, **changes):
    """Invoke the pure classifier with an independently supplied review policy and exact context."""

    options = {"event": "pull_request", "base": "develop", "head": HEAD, "commit": BASE,
               "policy": POLICY, "read": lambda reference: b"unused", **changes}
    reviewed = json.dumps(Manifest(payload)).encode() if manifest is None else manifest

    return policy.Profile(payload, reviewed, **options)


@pytest.mark.parametrize("status", ["A", "M", "D"])
def test_ExactCompleteReviewedInventoryAdmitsRegularFileChanges(status):
    """Only the independent reviewed old/new object inventory grants the passive profile."""

    assert Classify(Change("src/fuzzy1337/shell.py", status)) == "passive", (
        "An exact independently reviewed regular-file change was not admitted."
    )


@pytest.mark.parametrize("mutation", ["extra", "missing", "hash", "mode", "order", "record"])
def test_PassiveBranchCannotGrantUnreviewedMixedOrAlteredChanges(mutation):
    """Exact regular shared sources and routing files require reviewed blob identities too."""

    payload = Change("src/fuzzy1337/shell.py") + Change("CHANGELOG.md")
    manifest = Manifest(payload)

    if mutation == "extra":
        payload += Change("src/fuzzy1337/executor.py")

    elif mutation == "missing":
        payload = Change("CHANGELOG.md")

    elif mutation == "hash":
        payload = payload.replace(b"c" * 40, b"d" * 40)

    elif mutation == "mode":
        payload = payload.replace(b"100644", b"100755")

    elif mutation == "order":
        manifest["changes"].reverse()

    else:
        manifest["changes"][0] = "not a reviewed record"

    assert Classify(payload, json.dumps(manifest).encode()) == "hold", (
        "The request branch bypassed the separately reviewed complete content inventory."
    )


@pytest.mark.parametrize("payload", [
    b"", b"\0", b"invalid\0CHANGELOG.md\0", Change()[:-1], Change() + b"extra\0",
    Change() * 2, Change().replace(b"100644", b"120000"),
    Change().replace(b" M\0", b" R100\0"), Change().replace(b"b" * 40, b"b" * 7),
    Change().replace(b"b" * 40, b"c" * 40), Change().replace(b"b" * 40, b"0" * 40),
    Change(status="A").replace(b"0" * 40, b"b" * 40),
    Change(status="D").replace(b"0" * 40, b"c" * 40),
    Change().replace(b"CHANGELOG.md", b"\xff"), Change("../CHANGELOG.md"),
    Change("/CHANGELOG.md"), Change("docs//file"), Change("docs/./file"),
    Change("CHANGELOG.md\nforged"), b"x" * (policy.MAX_BYTES + 1),
])
def test_IncompleteAmbiguousExcessiveOrUnsafeRawDiffIsHeld(payload):
    """No missing byte, duplicate, link, rename, abbreviated hash or unsafe path is truncated."""

    assert Classify(payload, json.dumps(Manifest(Change())).encode()) == "hold", (
        "Invalid raw Git framing was accepted as a complete reviewed passive decision."
    )


@pytest.mark.parametrize("manifest", [
    b"", b"[]", b"{}", b"{", b'{"schema_version":1,"schema_version":1}',
    b"x" * (policy.MAX_BYTES + 1),
])
def test_MissingMalformedDuplicateOrOversizeTrustedPolicyIsHeld(manifest):
    """An unavailable policy is a visible hold rather than active or passive acceptance."""

    assert Classify(Change(), manifest) == "hold", "Invalid manifest granted passive acceptance."


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("base_commit", "0" * 40),
    ("head_ref", "feature/passive-batch-other"),
    ("changes", {}), ("extra", None),
])
def test_ManifestSelectionAndExactSchemaCannotDrift(field, value):
    """Policy version, reviewed base and branch must match the actual invocation."""

    manifest = Manifest(Change())
    manifest[field] = value
    assert Classify(Change(), json.dumps(manifest).encode()) == "hold", (
        "A different review base, request or manifest shape granted passive acceptance."
    )


@pytest.mark.parametrize("options", [{"commit": "short"}, {"policy": "invalid"}])
def test_ExactReviewedObjectIdentifiersAreRequired(options):
    """Abbreviated or malformed policy/base references cannot select trusted bytes."""

    assert Classify(Change(), **options) == "hold", "Invalid reviewed object pin passed admission."


def test_DiffFileAndByteCeilingsFailClosed(monkeypatch):
    """A complete passive prefix cannot hide inventory or byte overflow."""

    payload = Change() + Change("docs/REPORTING.md")
    manifest = json.dumps(Manifest(payload)).encode()
    monkeypatch.setattr(policy, "MAX_FILES", 1)
    assert Classify(payload, manifest) == "hold", "Excessive changed file count was truncated."
    monkeypatch.setattr(policy, "MAX_FILES", 2)
    monkeypatch.setattr(policy, "MAX_BYTES", len(payload) - 1)
    assert Classify(payload, manifest) == "hold", "Excessive raw diff bytes were truncated."


@pytest.mark.parametrize("event,base,head", [
    ("pull_request", "master", HEAD), ("push", "master", HEAD),
    ("pull_request", "develop", "feature/ordinary"), ("push", "develop", HEAD),
])
def test_OrdinaryWorkAndMasterKeepPreexistingFullAcceptance(event, base, head):
    """Only an explicit develop request enters the new classifier; master routing is untouched."""

    assert Classify(b"", b"", event=event, base=base, head=head) == "full", (
        "Ordinary or master acceptance was silently reduced by passive routing."
    )


@pytest.mark.parametrize("mutation", ["none", "content", "two-pins", "wrong-pin", "other-path"])
def test_OnlyOneExactRoutingPolicyLiteralCanBeNormalized(mutation):
    """Bootstrap breaks the commit self-reference without normalizing any other reviewed bytes."""

    payload = Change(policy.PIN_PATH)
    workflow = b'env:\n  PASSIVE_POLICY_COMMIT: "' + POLICY.encode() + b'"\n'
    manifest = Manifest(payload)
    record = manifest["changes"][0]
    record["new_blob"] = None
    record["normalized_sha256"] = hashlib.sha256(
        policy.NormalizedWorkflow(workflow, POLICY)
    ).hexdigest()

    if mutation == "content":
        workflow += b"unexpected: changed\n"

    elif mutation == "two-pins":
        workflow += workflow

    elif mutation == "wrong-pin":
        workflow = workflow.replace(POLICY.encode(), b"e" * 40)

    elif mutation == "other-path":
        record["path"] = "src/fuzzy1337/shell.py"

    result = Classify(payload, json.dumps(manifest).encode(), read=lambda reference: workflow)
    assert result == ("passive" if mutation == "none" else "hold"), (
        "Workflow normalization changed bytes outside its one exact policy pin literal."
    )


@pytest.mark.parametrize("name,job", WORKFLOWS.items())
def test_StandaloneAcceptancesVetoRequestsWithoutAddingRouterJobs(name, job):
    """An optional context veto suppresses work without granting acceptance or using a runner."""

    workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
    events = workflow.get("on", workflow.get(True))
    assert events["push"] == {"branches": ["master"]}, "Master push acceptance was filtered."
    assert "integration-scope" not in workflow["jobs"], (
        "Optional acceptance added another router runner instead of applying its context veto."
    )
    assert all("uses" not in value for value in workflow["jobs"].values()), (
        "An optional acceptance acquired an unrelated reusable-workflow runner."
    )
    selected = workflow["jobs"][job]
    assert "needs" not in selected and " ".join(selected["if"].split()).startswith(
        OPTIONAL_VETO
    ), "An active standalone job can run for a requested passive or held batch."
    assert "github.event_name == 'push'" in selected["if"] and selected["steps"], (
        "Routing removed original stable push execution or genuine acceptance steps."
    )


def test_SharedRouterNeverExecutesCandidateCodeAndHoldsFailures():
    """The bootstrap loader runs only separately pinned policy before any candidate execution."""

    workflow = yaml.safe_load((ROOT / policy.PIN_PATH).read_text())
    job = workflow["jobs"]["classify"]
    steps = job["steps"]
    assert workflow["permissions"] == {"contents": "read"}, "Router acquired write authority."
    trusted = next(step for step in steps
                   if step.get("name", "").startswith("Check out the separate"))
    assert trusted["with"]["ref"] == "${{ env.PASSIVE_POLICY_COMMIT }}" and not trusted[
        "with"
    ]["persist-credentials"], "Policy checkout is not separately immutable and credential-free."
    command = next(step["run"] for step in steps if step.get("id") == "classify")
    anchor = 'git merge-base --is-ancestor "$PASSIVE_POLICY_COMMIT" '
    anchor += 'refs/remotes/origin/feature/ci-batch-policies'
    assert 0 <= command.find(anchor) < command.find("python3 -I"), (
        "The loader must establish policy-branch provenance before executing the pinned helper."
    )
    assert "python3 -I ../trusted-policy/tools/passive_scope.py" in command and (
        "--no-ext-diff --raw -z --no-renames --abbrev=40" in command
    ), "Router executes head policy or consumes incomplete/ambiguous Git metadata."
    assert steps[-1]["if"] == "always()" and "exit 1" in steps[-1]["run"], (
        "Unknown or failed requested scope does not visibly fail its routing gate."
    )


def test_ActualRawGitDiffAndPinnedStyleScriptInvocationUseExactContent(tmp_path):
    """Exercise the actual Git producer and isolated helper CLI with independent manifest bytes."""

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "fixture@example.invalid"],
                   check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Owned fixture"], check=True)
    source = tmp_path / "CHANGELOG.md"
    source.write_text("Original synthetic content\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "CHANGELOG.md"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "Original fixture"], check=True)
    source.write_text("Revised synthetic content\n")
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qam", "Revised fixture"], check=True)
    raw = subprocess.run(["git", "-C", str(tmp_path), "diff", "--no-ext-diff", "--raw", "-z",
                          "--no-renames", "--abbrev=40", "HEAD^", "HEAD"],
                         check=True, capture_output=True).stdout
    manifest = tmp_path / "independent-policy.json"
    manifest.write_text(json.dumps(Manifest(raw)))
    command = [sys.executable, "-I", str(Path(policy.__file__)), "--event", "pull_request",
               "--base", "develop", "--head-ref", HEAD, "--base-commit", BASE,
               "--policy-commit", POLICY, "--manifest", str(manifest)]
    result = subprocess.run(command, input=raw, capture_output=True, check=False, cwd=tmp_path)
    assert result.returncode == 0 and result.stdout == b"profile=passive\n" and not result.stderr, (
        "Real raw Git framing and the isolated trusted-script CLI disagree."
    )
    manifest.unlink()
    held = subprocess.run(command, input=raw, capture_output=True, check=False, cwd=tmp_path)
    assert held.returncode == 0 and held.stdout == b"profile=hold\n" and not held.stderr, (
        "Unavailable separately reviewed policy did not produce an explicit fixed hold."
    )


def test_RealNormalizedWorkflowBlobAndCliAreBoundedBeforeAllocation(tmp_path, monkeypatch, capsys):
    """Use real bootstrap Git reads and refuse oversized blobs before loading their bytes."""

    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    workflow = b'env:\n  PASSIVE_POLICY_COMMIT: "' + POLICY.encode() + b'"\n'
    blob = subprocess.run(["git", "-C", str(tmp_path), "hash-object", "-w", "--stdin"],
                          input=workflow, capture_output=True, check=True).stdout.strip()
    raw = Change(policy.PIN_PATH).replace(b"c" * 40, blob)
    manifest = Manifest(raw)
    record = manifest["changes"][0]
    record["new_blob"] = None
    record["normalized_sha256"] = hashlib.sha256(
        policy.NormalizedWorkflow(workflow, POLICY)
    ).hexdigest()
    selected = tmp_path / "trusted.json"
    selected.write_text(json.dumps(manifest))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["trusted-scope.py", "--event", "pull_request", "--base",
                                     "develop", "--head-ref", HEAD, "--base-commit", BASE,
                                     "--policy-commit", POLICY, "--manifest", str(selected)])
    from io import BytesIO

    class Input:
        """Expose only fixed raw bytes at the actual CLI binary stdin boundary."""

        buffer = BytesIO(raw)

    monkeypatch.setattr(sys, "stdin", Input())
    assert policy.Main() == 0 and capsys.readouterr().out == "profile=passive\n", (
        "Real candidate blob read did not match the exact normalized reviewed workflow."
    )
    large = subprocess.run(["git", "hash-object", "-w", "--stdin"],
                           input=b"x" * (policy.MAX_BYTES + 1), capture_output=True,
                           check=True).stdout.strip()
    Input.buffer = BytesIO(raw.replace(blob, large))
    assert policy.Main() == 0 and capsys.readouterr().out == "profile=hold\n", (
        "An oversized untrusted workflow blob was admitted to the normalization exception."
    )


@pytest.mark.parametrize("name", [
    *WORKFLOWS, "native-ci-diagnostic.yml", "intel-source-acceptance.yml",
])
def test_ExistingDiagnosticMarkersCannotBypassRequestedPassiveRouting(name):
    """Ordinary draft diagnostics remain full; passive/hold scopes cannot launch checkpoint work."""

    workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())

    for identity, job in workflow["jobs"].items():
        assert identity != "integration-scope" and "needs" not in job and " ".join(
            job["if"].split()
        ).startswith(
            OPTIONAL_VETO
        ), "An old draft checkpoint marker can bypass a requested passive or held scope."
