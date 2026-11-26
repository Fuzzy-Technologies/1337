# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Protect immutable-manifest passive routing against false scope claims."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
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
    """The loader captures upstream policy data and executes only the actual base classifier."""

    workflow = yaml.safe_load((ROOT / policy.PIN_PATH).read_text())
    job = workflow["jobs"]["classify"]
    steps = job["steps"]
    assert workflow["permissions"] == {"contents": "read"}, "Router acquired write authority."
    checkouts = [step for step in steps if step.get("uses", "").startswith("actions/checkout@")]
    assert len(checkouts) == 1 and not checkouts[0]["with"]["persist-credentials"], (
        "The router must acquire candidate Git objects once without retaining credentials."
    )
    assert "PASSIVE_POLICY_COMMIT" not in str(workflow), (
        "An independent product PR must not edit a shared mutable policy pin."
    )
    command = next(step["run"] for step in steps if step.get("id") == "classify")
    assert "+refs/heads/feature/ci-batch-policies:refs/passive-policy-snapshot" in command and (
        "refs/passive-policy-snapshot^{commit}" in command
    ), "The policy snapshot must come from the fixed upstream registry ref."
    assert '$BASE_COMMIT:tools/passive_scope.py' in command and (
        'python3 -I "$RUNNER_TEMP/passive-base-scope.py"' in command
    ), "Only actual base-owned isolated classifier bytes may execute."
    assert '$policy_commit:$manifest_path' in command and (
        '"$policy_commit" -- "$manifest_path"' in command
    ), "Every policy read must use the captured immutable registry object and plain blob mode."
    assert '"100644 blob "' in command and '"$size" -le 1048576' in command, (
        "Registry manifests require regular files within the original manifest byte ceiling."
    )
    assert "--no-ext-diff --raw -z --no-renames --abbrev=40" in command, (
        "Router must consume the complete raw diff with full old/new object identities."
    )
    assert next(step for step in steps if step.get("id") == "classify")["env"][
        "POLICY_REGISTRY_URL"
    ] == "${{ github.server_url }}/${{ github.repository }}.git", (
        "Registry authority must come from the upstream event context, never candidate input."
    )
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
    assert result.returncode == 0 and (
        result.stdout.splitlines() == [b"profile=passive"] and not result.stderr
    ), (
        "Real raw Git framing and the isolated trusted-script CLI disagree."
    )
    manifest.unlink()
    held = subprocess.run(command, input=raw, capture_output=True, check=False, cwd=tmp_path)
    assert held.returncode == 0 and (
        held.stdout.splitlines() == [b"profile=hold"] and not held.stderr
    ), (
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


def Git(root, *arguments, input=None):
    """Run only local fixture Git operations with explicit ownership and no product execution."""

    return subprocess.run(["git", "--no-replace-objects", "-C", str(root), *arguments],
                          input=input, check=True, capture_output=True).stdout


def RegistryPath(base, head, raw):
    """Independently construct the documented content-addressed per-batch manifest selection."""

    framed = b"1337-passive-registry-v1\0" + base.encode("ascii") + b"\0" + head.encode(
        "utf-8") + b"\0" + raw

    return "contracts/passive-batches/" + hashlib.sha256(framed).hexdigest() + ".json"


@pytest.fixture(name="registryFixture")
def RegistryFixture(request):
    """Create two independent candidate commits and one upstream registry with both raw entries."""

    if sys.platform != "linux":
        pytest.skip("Registry routing exercises the Ubuntu workflow's Bash and Git fixture")

    tmpPath = request.getfixturevalue("tmp_path")
    upstream = tmpPath / "upstream"
    upstream.mkdir()
    Git(upstream, "init", "-q")
    Git(upstream, "config", "user.name", "Owned registry fixture")
    Git(upstream, "config", "user.email", "registry@example.invalid")
    (upstream / "tools").mkdir()
    (upstream / "tools/passive_scope.py").write_bytes(Path(policy.__file__).read_bytes())
    Git(upstream, "add", "tools/passive_scope.py")
    Git(upstream, "commit", "-qm", "Existing base classifier")
    base = Git(upstream, "rev-parse", "HEAD").decode().strip()
    requests = {}

    for name in ("first", "second"):
        head = "feature/passive-batch-" + name
        Git(upstream, "checkout", "-qb", head, base)
        (upstream / (name + ".txt")).write_text("Independent reviewed offline content\n")
        (upstream / "tools/passive_scope.py").write_text(
            'from pathlib import Path\nPath("untrusted-helper-executed").write_text("bad")\n'
            'print("profile=passive")\n')
        Git(upstream, "add", ".")
        Git(upstream, "commit", "-qm", "Independent candidate " + name)
        commit = Git(upstream, "rev-parse", "HEAD").decode().strip()
        raw = Git(upstream, "diff", "--no-ext-diff", "--raw", "-z", "--no-renames",
                  "--abbrev=40", base, commit)
        requests[name] = {"head": head, "commit": commit, "raw": raw,
            "path": RegistryPath(base, head, raw), "manifest": {"schema_version": 1,
                "base_commit": base, "head_ref": head, "changes": policy.Changes(raw)}}

    Git(upstream, "checkout", "-qb", "feature/ci-batch-policies", base)

    for request in requests.values():
        path = upstream / request["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(request["manifest"]))

    (upstream / "tools/passive_scope.py").write_text(
        'from pathlib import Path\nPath("registry-helper-executed").write_text("bad")\n'
        'print("profile=passive")\n')
    Git(upstream, "add", "contracts", "tools/passive_scope.py")
    Git(upstream, "commit", "-qm", "Two independent reviewed manifests")
    snapshot = Git(upstream, "rev-parse", "HEAD").decode().strip()

    for name, request in requests.items():
        clone = tmpPath / name
        subprocess.run(["git", "clone", "-q", "--no-local", str(upstream), str(clone)],
                       check=True, capture_output=True)
        Git(clone, "checkout", "-q", request["commit"])
        request["clone"] = clone

    return {"upstream": upstream, "base": base, "snapshot": snapshot, "requests": requests}


def RunRegistry(fixture, name, *, rendezvous=None, advance=False, **context):
    """Execute all three routing scripts with local transport and bounded subprocesses."""

    request = fixture["requests"][name]
    root = request["clone"]
    temporary = root / ".routing"
    temporary.mkdir()
    output = temporary / "output"
    summary = temporary / "summary"
    environment = {**os.environ, "EVENT": "pull_request", "BASE": "develop",
        "HEAD_REF": request["head"], "BASE_COMMIT": fixture["base"],
        "HEAD_COMMIT": request["commit"], "POLICY_REGISTRY_URL": str(fixture["upstream"]),
        "RUNNER_TEMP": str(temporary), "GITHUB_OUTPUT": str(output),
        "GITHUB_STEP_SUMMARY": str(summary), "PASSIVE_POLICY_COMMIT": request["commit"], **context}

    if rendezvous is not None or advance:
        binary = temporary / "bin"
        binary.mkdir()
        shim = binary / "git"
        shim.write_text('''#!/bin/bash
if [[ "${2-}" == fetch && -n "${FETCH_RENDEZVOUS-}" ]]; then
  echo "$$" > "$FETCH_RENDEZVOUS/$REQUEST_NAME.fetch"
  deadline=$((SECONDS + 5))
  while ! test -f "$FETCH_RENDEZVOUS/first.fetch" || ! test -f "$FETCH_RENDEZVOUS/second.fetch"; do
    test "$SECONDS" -lt "$deadline" || exit 97
    sleep 0.01
  done
fi
if [[ "${2-}" == ls-tree && -n "${ADVANCE_REGISTRY_TO-}" ]]; then
  ref=refs/heads/feature/ci-batch-policies
  "$REAL_GIT" -C "$POLICY_REGISTRY_URL" update-ref "$ref" "$ADVANCE_REGISTRY_TO"
fi
exec "$REAL_GIT" "$@"
''')
        shim.chmod(0o755)
        environment.update({"REAL_GIT": shutil.which("git"), "FETCH_RENDEZVOUS":
                            str(rendezvous) if rendezvous is not None else "",
                            "ADVANCE_REGISTRY_TO": fixture["base"] if advance else "",
                            "REQUEST_NAME": name,
                            "PATH": str(binary) + os.pathsep + os.environ["PATH"]})

    workflow = yaml.safe_load((ROOT / policy.PIN_PATH).read_text())
    steps = workflow["jobs"]["classify"]["steps"]
    default = next(step["run"] for step in steps if step.get("id") == "default")
    command = next(step["run"] for step in steps if step.get("id") == "classify")
    defaultStep = subprocess.run(["bash", "-c", default], cwd=root, env=environment, check=False,
                                 capture_output=True, timeout=10)
    assert defaultStep.returncode == 0, (
        f"Routing default step exited with {defaultStep.returncode}: {defaultStep.stderr!r}"
    )
    initial = dict(line.split("=", 1) for line in output.read_text().splitlines())["profile"]

    if initial == "hold":
        subprocess.run(["bash", "-c", command], cwd=root, env=environment,
                       capture_output=True, check=False, timeout=20)

    profile = dict(line.split("=", 1) for line in output.read_text().splitlines())["profile"]
    final = subprocess.run(["bash", "-c", steps[-1]["run"]], cwd=root,
                           env={**environment, "PROFILE": profile},
                           capture_output=True, check=False, timeout=10)
    assert not any((root / marker).exists() for marker in (
        "untrusted-helper-executed", "registry-helper-executed"
    )), (
        "Neither candidate nor registry self-authorizing classifiers may execute."
    )

    return profile, final.returncode, summary.read_text()


def test_TwoIndependentRequestsUseOneImmutableUpstreamRegistryConcurrently(
    registryFixture, tmp_path,
):
    """Both exact independently reviewed branches pass without any shared product-file edits."""

    rendezvous = tmp_path / "rendezvous"
    rendezvous.mkdir()

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda name: RunRegistry(registryFixture, name,
                                                       rendezvous=rendezvous), ("first", "second")))

    assert all(profile == "passive" and status == 0 and registryFixture["snapshot"] in summary
               for profile, status, summary in results), (
        "Independent exact batches must both pass from the same captured immutable registry."
    )
    assert registryFixture["requests"]["first"]["path"] != registryFixture["requests"][
        "second"
    ]["path"], "Independent branch/diff selections must use separate registry entries."
    assert len({path.read_text().strip() for path in rendezvous.glob("*.fetch")}) == 2, (
        "Two distinct loader processes must rendezvous while fetching the same registry."
    )


def test_CapturedRegistryCommitSurvivesUpstreamRefMovement(registryFixture):
    """A branch update after capture cannot replace the immutable manifest used by this run."""

    profile, status, summary = RunRegistry(registryFixture, "first", advance=True)
    current = Git(registryFixture["upstream"], "rev-parse",
                  "refs/heads/feature/ci-batch-policies").decode().strip()
    assert current == registryFixture["base"] and current != registryFixture["snapshot"], (
        "The fixture must move the upstream branch after capturing its immutable snapshot."
    )
    assert profile == "passive" and status == 0 and registryFixture["snapshot"] in summary, (
        "Upstream branch movement must not replace an already captured policy snapshot."
    )


@pytest.mark.parametrize("fault", ["cross-swap", "wrong-base", "wrong-head", "wrong-blob",
    "wrong-old-blob", "mode", "mixed", "missing", "normalized", "symlink", "oversize",
    "own-policy", "missing-ref"])
def test_RegistryCannotAuthorizeCrossedUnreviewedOrCandidateSuppliedPolicy(registryFixture, fault):
    """Only one exact raw regular-file manifest in the real upstream snapshot grants acceptance."""

    upstream = registryFixture["upstream"]
    request = registryFixture["requests"]["first"]
    selected = upstream / request["path"]
    manifest = json.loads(selected.read_text())

    if fault == "cross-swap":
        manifest = registryFixture["requests"]["second"]["manifest"]

    elif fault == "wrong-base":
        manifest["base_commit"] = "0" * 40

    elif fault == "wrong-head":
        manifest["head_ref"] = registryFixture["requests"]["second"]["head"]

    elif fault in ("wrong-blob", "wrong-old-blob", "mode"):
        key = {"wrong-blob": "new_blob", "wrong-old-blob": "old_blob", "mode": "new_mode"}[fault]
        manifest["changes"][0][key] = "100755" if fault == "mode" else "e" * 40

    elif fault == "mixed":
        manifest["changes"].pop()

    elif fault == "normalized":
        manifest["changes"][0].update({"new_blob": None, "normalized_sha256": "0" * 64})

    if fault in ("missing", "own-policy"):
        selected.unlink()

        if fault == "own-policy":
            local = request["clone"] / request["path"]
            local.parent.mkdir(parents=True)
            local.write_text(json.dumps(manifest))
            Git(request["clone"], "update-ref", "refs/passive-policy-snapshot", request["commit"])

    elif fault == "symlink":
        selected.unlink()
        selected.symlink_to("../../tools/passive_scope.py")

    else:
        selected.write_text("x" * (policy.MAX_BYTES + 1) if fault == "oversize" else
                           json.dumps(manifest))

    Git(upstream, "add", "contracts")
    Git(upstream, "commit", "--allow-empty", "-qm", "Untrusted or inconsistent fixture policy")

    if fault == "missing-ref":
        Git(request["clone"], "update-ref", "refs/passive-policy-snapshot",
            registryFixture["snapshot"])
        Git(upstream, "update-ref", "-d", "refs/heads/feature/ci-batch-policies")

    profile, status, _ = RunRegistry(registryFixture, "first")
    assert profile == "hold" and status == 1, (
        "Missing, crossed, normalized, unsafe or candidate-owned policy must fail closed."
    )


@pytest.mark.parametrize("field", ["BASE_COMMIT", "HEAD_COMMIT"])
def test_RegistryRejectsAnIncorrectActualBaseOrHead(registryFixture, field):
    """Manifest selection cannot override the actual Git checkout or base ancestry boundary."""

    profile, status, _ = RunRegistry(registryFixture, "first", **{field: "e" * 40})
    assert profile == "hold" and status == 1, (
        "Incorrect actual base or head commits must fail before passive acceptance."
    )


@pytest.mark.parametrize("context", [{"EVENT": "push"}, {"BASE": "master"},
                                    {"HEAD_REF": "feature/ordinary"}])
def test_RegistryMigrationKeepsOrdinaryAndMasterRoutesUnchanged(registryFixture, context):
    """Ordinary event contexts keep full acceptance without requiring registry policy."""

    profile, status, summary = RunRegistry(registryFixture, "first", **context)
    assert profile == "full" and status == 0 and "Passive policy registry:" not in summary, (
        "Registry migration must preserve ordinary/master scope without passive verification."
    )
