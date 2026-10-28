# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Original fixed IPv4 seed and distinct current fresh-fixture authority, never acquisition.

Setup preserves the reviewed original native-state seed. FreshSetup creates independent new
fixture authority and never renews its selected window. Both deliberately refuse IPv6.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from types import ModuleType

OWNER = "actor:owned-response-product"
ATTESTER = "attester:independent-source-consent"
WORKSPACE = "owned-response-product"
SCOPE = "owned-source"
MAX_SEED_SOURCE_BYTES = 1024 * 1024


def LoadSeed() -> tuple[ModuleType, dict]:
    """Load only the fixed reviewed original Setup/Inspect bytes, with separate source binding.

    Returns:
        Original helper namespace and observed exact source path/hash. The caller must reconcile
        this observation against its reviewed checkpoint before authorizing actual setup.
    """

    path = Path(__file__).resolve().with_name("owned_response_product_runner.py")

    with path.open("rb") as stream:
        raw = stream.read(MAX_SEED_SOURCE_BYTES + 1)

    if len(raw) > MAX_SEED_SOURCE_BYTES:
        raise ValueError("Fixed reviewed original seed source exceeds its byte ceiling")

    module = ModuleType("owned_content_response_original_seed")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)

    return module, {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}


def Setup(config: dict, *, enabled: bool = False) -> dict:
    """Create one fresh explicitly selected owned IPv4 SDK workspace with original native triage.

    Args:
        config: Exactly absolute workspace, canonical literal content URL and fixed seed owner.
        enabled: Independent exact execution opt-in; false performs no reads or store activity.

    Returns:
        Actual original Setup/Inspect values unchanged, plus explicit later SDK selection and
        observed fixed helper hash. This is not acquisition, consent verification or acceptance.
    """

    if enabled is not True:
        raise PermissionError("Fresh owned SDK setup requires explicit execution opt-in")

    if type(config) is not dict or set(config) != {"workspace", "url", "owner_reference"} or (
        any(type(value) is not str or not value for value in config.values())
    ):
        raise ValueError("Fresh SDK setup requires its entire explicit selection")

    root = Path(config["workspace"])

    if not root.is_absolute() or ".." in root.parts or config["owner_reference"] != OWNER:
        raise ValueError("Fresh SDK setup requires its absolute workspace and original fixed actor")

    from fuzzy1337.adapters.owned_content_response import Destination

    address, _port, _path, _authority = Destination(config["url"])

    if address != "127.0.0.1":
        raise ValueError("The reviewed original seed supports only explicitly selected IPv4")

    if root.exists() or root.is_symlink():
        raise FileExistsError("Fresh SDK setup refuses an existing workspace without changing it")

    original, source = LoadSeed()

    if original.OWNER != OWNER or original.WORKSPACE != WORKSPACE or OWNER == ATTESTER:
        raise ValueError("Reviewed original actor/workspace bindings changed")

    # Original Create owns its atomic absent-root mkdir; precreating it would defeat that contract.
    actual = original.Setup({"workspace": str(root), "url": config["url"]})

    return {"selection": {"workspace": str(root), "url": config["url"], "ip": address,
        "scope_id": SCOPE, "owner_reference": OWNER, "attester_reference": ATTESTER},
        "original_setup": actual, "seed_source": source}


def FreshSelection(config: dict, now: datetime) -> dict:
    """Admit explicit new fixture authority only within its original current aware time window.

    Args:
        config: Closed new fixture identity, absolute workspace, literal IPv4 URL and times.
        now: Actual current aware time; a delayed setup receives no replacement window.

    Returns:
        New independent identity bindings, never the original seed's authority or scope.
    """

    fields = {"fixture_id", "workspace", "url", "consent_valid_from", "consent_valid_until"}

    if type(config) is not dict or set(config) != fields or any(
        type(value) is not str or not value for value in config.values()
    ):
        raise ValueError("Fresh fixture setup requires its entire explicit selection")

    fixture = config["fixture_id"]

    if not 8 <= len(fixture) <= 64 or re.fullmatch(
        r"[a-z0-9]+(?:-[a-z0-9]+)*", fixture) is None or fixture in (
            WORKSPACE, SCOPE, "historical", "unit-only", "mock-run-0001"
    ):
        raise ValueError("Historical and source-only mock identities cannot authorize fresh setup")

    root = Path(config["workspace"])

    if not root.is_absolute() or ".." in root.parts:
        raise ValueError("Fresh fixture workspace must be an explicit absolute owner")

    from fuzzy1337.adapters.owned_content_response import Destination

    address, port, path, _authority = Destination(config["url"])

    if address != "127.0.0.1" or path != "/research/content" or config["url"] != (
        f"http://127.0.0.1:{port}/research/content"):
        raise ValueError("Fresh fixture selects only its actual owned IPv4 content URL")

    start, end = [datetime.fromisoformat(config[key]) for key in (
        "consent_valid_from", "consent_valid_until")]

    if not isinstance(now, datetime) or any(value.tzinfo is None or value.utcoffset() is None
        for value in (start, end, now)) or not (
            0 < (end - start).total_seconds() <= 900 and start <= now < end):
        raise PermissionError("Fresh fixture consent is not currently valid; never renew it")

    if [value.astimezone(timezone.utc).isoformat() for value in (start, end)] != [
        config["consent_valid_from"], config["consent_valid_until"]]:
        raise ValueError("Fresh fixture consent times must use their exact canonical UTC spelling")

    identity = "owned-content-header-" + fixture

    return {"workspace_id": identity, "scope_id": identity, "owner_reference": "actor:" + identity,
        "attester_reference": "attester:" + identity, "consent_reference": "consent:" + identity}


def FreshSetup(config: dict, *, enabled: bool = False, current_time_provider=None) -> dict:
    """Create a distinct test fixture with current consent, unrelated originals and native triage.

    Args:
        config: Exact FreshSelection inputs, independently selected before actual execution.
        enabled: Exact independent setup opt-in; false performs no time reads or store activity.
        current_time_provider: Trusted deterministic unit-test clock; absent uses real UTC now.

    Returns:
        Original reopened state and new scope. Capture/analysis remain separate operations.
    """

    if enabled is not True:
        raise PermissionError("Fresh fixture setup requires independent execution opt-in")

    now = datetime.now(timezone.utc) if current_time_provider is None else current_time_provider()
    selected = FreshSelection(config, now)
    root = Path(config["workspace"])

    if root.exists() or root.is_symlink():
        raise FileExistsError("Fresh fixture setup never replaces an existing workspace")

    from fuzzy1337.evidence import EvidenceProvenance, LocalEvidenceStore
    from fuzzy1337.findings import Finding, FindingStatus
    from fuzzy1337.model import (
        LocalModelStore,
        ModelProvenance,
        ObjectIdentity,
        ObjectKind,
        SecurityObject,
    )
    from fuzzy1337.scope import (
        AuthorizationState,
        LocalScopeStore,
        ScopeAuthorization,
        ScopeSnapshot,
        Target,
        TargetKind,
    )
    from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

    workspace_id = selected["workspace_id"]
    scopes = LocalScopeStore(root)
    workspaces = LocalWorkspaceStore(root)
    workspaces.Create(WorkspaceConfiguration("Fresh content header SDK fixture"), workspace_id)
    models = LocalModelStore(root)
    model = models.Create()
    consent = ScopeAuthorization(AuthorizationState.GRANTED, selected["attester_reference"],
        selected["consent_reference"], config["consent_valid_from"], config["consent_valid_until"])
    targets = (Target(TargetKind.URL, config["url"]), Target(TargetKind.IP, "127.0.0.1"))
    scopes.Create(ScopeSnapshot(selected["scope_id"], workspace_id,
        authorization=consent, targets=targets, allow=targets))
    original = LocalEvidenceStore(root / "evidence").Put(
        b"fresh unrelated synthetic native source; no tool execution\n", "unrelated-native-source",
        "application/octet-stream", EvidenceProvenance(workspace_id, "scope:unrelated-" +
            workspace_id, "native.fixture", "1", "fixture", now.isoformat(), now.isoformat()))
    provenance = ModelProvenance("native.fixture", "job:unrelated-" + workspace_id,
        now.isoformat(), "scope:unrelated-" + workspace_id, "artifact:unrelated-" + workspace_id,
        "fixture", (original.reference,))
    asset = SecurityObject(ObjectIdentity(workspace_id, ObjectKind.ASSET,
        "native-fixture:" + workspace_id), {"source": "native.fixture"}, (provenance,))
    finding = Finding(asset.Reference(), "owned.native-fixture", "package:unrelated",
        "Fresh unrelated synthetic existing finding", (provenance,))
    proposed, _ = model.Apply(objects=(asset, finding.ToObject(workspace_id)))
    saved = models.Save(proposed, expected_revision=model.revision)
    triaged = replace(finding, status=FindingStatus.CONFIRMED,
        status_reason="Independent native fixture triage must survive the integrated pipeline")
    proposed, _ = saved.Apply(objects=(triaged.ToObject(workspace_id),))
    saved = models.Save(proposed, expected_revision=saved.revision)
    workspace = workspaces.Open()
    workspaces.Save(replace(workspace,
        object_references=tuple(item.Reference() for item in saved.objects),
        job_references=(provenance.run_reference,), evidence_references=(original.reference,),
        evidence_record_references=(original.evidence_id,)))
    reader, source = LoadSeed()

    return {"state": reader.Inspect(root), "scope": scopes.Open(selected["scope_id"]).ToDict(),
        "reader_source": source}
