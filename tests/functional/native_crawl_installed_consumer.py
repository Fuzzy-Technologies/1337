# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Fixed genuine installed-wheel consumer; records actual owner results without replacing
success."""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

import fuzzy1337
from fuzzy1337.adapters import ImpactLevel, SerializeContract
from fuzzy1337.adapters.native_crawl import NativeCrawlAdapter
from fuzzy1337.evidence import LocalEvidenceStore
from fuzzy1337.executors import LocalExecutor
from fuzzy1337.findings import Findings, FindingStatus, TransitionFinding
from fuzzy1337.model import LocalModelStore, ModelProvenance, ObjectKind
from fuzzy1337.native_crawl import NativeCrawlLimits
from fuzzy1337.native_crawl_workflow import PlanNativeCrawl, RunNativeCrawl
from fuzzy1337.native_web import PlanNativeWebScan, RunNativeWebScan
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy, PolicyConfirmation, PolicyEngine
from fuzzy1337.requests import (
    BodyKind,
    Endpoint,
    ProjectRequests,
    RequestsFromObject,
    RequestTemplate,
)
from fuzzy1337.scan_commands import CreateWorkspace, OpenWorkspace
from fuzzy1337.scope import (
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore

OWNER = "actor:independent-crawl-operator"
ATTESTER = "attester:independent-crawl-consent"
WORKSPACE_ID = "native-crawl-acceptance"


def Detached(value) -> object:
    """Detach actual public owner contracts without constructing expected observations."""

    return json.loads(SerializeContract(value))


def Policy(config: dict, *, git: bool = False) -> ImpactPolicy:
    """Require explicit distinct SAFE crawl and STANDARD Git permissions from actual owners."""

    impact = ImpactLevel.STANDARD if git else ImpactLevel.SAFE
    capability, provider = ("web.git-head-check", "native.web-check") if git else (
        "http.owned-loopback-crawl", "native.crawl")
    permissions = () if config.get("negative") == "policy-denied" else (
        CapabilityPermission(capability, provider, impact),)

    return ImpactPolicy("independent-native-crawl", maximum_impact=impact, permissions=permissions)


def Inspect(root: Path, extra_ids: tuple[str, ...] = ()) -> dict:
    """Reopen actual canonical model/workspace and original manifests, including unattached
    custody."""

    workspace = LocalWorkspaceStore(root).Open()
    model = LocalModelStore(root).Open()
    evidence = LocalEvidenceStore(root / "evidence")
    originals = {}

    for identity in sorted({*workspace.evidence_record_references, *extra_ids}):
        record = evidence.Get(identity)
        originals[identity] = {"manifest": record.ToDict(),
                               "data_hex": evidence.Read(record.reference).hex()}

    requests = []

    for endpoint in model.Objects(ObjectKind.ENDPOINT):
        if "request_templates" in endpoint.attributes:
            requests.append({"endpoint_reference": endpoint.Reference(),
                "templates": [template.ToDict() for template in RequestsFromObject(endpoint)]})

    return {"workspace": workspace.ToDict(), "model": model.ToDict(), "originals": originals,
        "requests": requests, "findings": [{"reference": item.ToObject(WORKSPACE_ID).Reference(),
            **item.ToAttributes(), "provenance": Detached(item.provenance)}
            for item in Findings(model)]}


def Setup(config: dict) -> dict:
    """Create only explicitly selected exact URL/IP scopes and independent recorded consent."""

    root = Path(config["workspace"])
    CreateWorkspace(root, WORKSPACE_ID, "Independent native crawl acceptance")
    seed = urlsplit(config["seed_url"])
    prior_template = RequestTemplate(Endpoint(WORKSPACE_ID, f"http://{seed.netloc}",
        seed.path, "GET"), body_kind=BodyKind.JSON)
    prior_provenance = ModelProvenance("fixture.native-crawl",
        "setup:independent-existing-request", datetime.now(UTC).isoformat(), "scope:crawl",
        Target(TargetKind.URL, config["seed_url"]).Reference(), "1")
    prior_endpoint = ProjectRequests((prior_template,), provenance=(prior_provenance,))
    prior_endpoint = replace(prior_endpoint, attributes={**dict(prior_endpoint.attributes),
        "independent_existing_attribute": "preserve-existing-structural-state"})
    model_store = LocalModelStore(root)
    model = model_store.Open()
    proposed, _ = model.Apply(objects=(prior_endpoint,))
    model_store.Save(proposed, expected_revision=model.revision)
    selected = tuple(Target(TargetKind.URL, url) for url in config["selected_urls"])
    address = Target(TargetKind.IP, "127.0.0.1")
    targets = (*selected, address)
    allowed = targets
    excluded = ()
    negative = config.get("negative")

    if negative == "unregistered":
        targets = tuple(item for item in targets if item != selected[0])
        allowed = targets

    elif negative == "ip-denied":
        allowed = selected

    elif negative == "excluded":
        excluded = (selected[0],)

    now = datetime.now(UTC)
    authorization = ScopeAuthorization(AuthorizationState.REVOKED if negative == "revoked" else
        AuthorizationState.GRANTED, ATTESTER, "consent:independent-native-crawl",
        (now - timedelta(minutes=1)).isoformat(), (now + timedelta(minutes=20)).isoformat())
    store = LocalScopeStore(root)
    store.Create(ScopeSnapshot("crawl", WORKSPACE_ID, authorization, targets=targets,
                               allow=allowed, exclusions=excluded))
    # Existing Git requires its separately selected owner to equal its recorded consent attester.
    store.Create(ScopeSnapshot("git-check", WORKSPACE_ID,
        replace(authorization, authority_reference=OWNER), targets=(*selected, address),
        allow=(*selected, address)))

    return {"state": Inspect(root), "crawl_attester": authorization.authority_reference,
            "selected_owner": OWNER}


def Crawl(config: dict) -> dict:
    """Run actual installed SDK with transparent observation of original execution/CAS
    acknowledgements."""

    root = Path(config["workspace"])
    negative = config.get("negative")
    actor = OWNER
    executions, saves = [], []
    original_execute = LocalExecutor.Execute
    original_save = LocalModelStore.Save
    original_authorize = PolicyEngine.Authorize
    limits = NativeCrawlLimits(**config.get("limits", {}))

    def CurrentOwner() -> str:
        """Supply an actual trusted reader whose original selected actor can drift independently."""

        return actor

    async def ObserveExecution(executor, request, **options):
        """Await actual installed execution and return the exact original result object
        unchanged."""

        nonlocal actor
        result = await original_execute(executor, request, **options)
        executions.append({"request": Detached(request), "execution": Detached(result.execution),
            "termination": result.termination.value, "stdout_hex": result.stdout.hex(),
            "stderr_hex": result.stderr.hex(), "events": [{"sequence": event.sequence,
                "kind": event.kind.value, "data_hex": event.data.hex(),
                "termination": None if event.termination is None else event.termination.value}
                for event in result.events]})

        if negative == "owner-before-save":
            actor = "actor:changed-after-real-worker"

        return result

    def ObserveSave(store, proposed, *, expected_revision):
        """Delegate actual CAS once; an explicit lost-ACK fault follows the real committed
        return."""

        prior = store.Open()
        actual = original_save(store, proposed, expected_revision=expected_revision)
        saves.append({"expected_revision": expected_revision, "prior_revision": prior.revision,
            "proposed_revision": proposed.revision, "acknowledged_revision": actual.revision,
            "exact_acknowledgement": actual == proposed})

        if negative == "lost-model-ack" and len(saves) == 1:
            raise OSError("owned post-commit acknowledgement interruption")

        return actual

    def ObserveAuthorize(engine, *args, **kwargs):
        """Return the real original grant, then change only the independent current actor reader."""

        nonlocal actor
        grant = original_authorize(engine, *args, **kwargs)

        if negative == "owner-grant-launch":
            actor = "actor:changed-after-real-grant"

        return grant

    LocalExecutor.Execute = ObserveExecution
    LocalModelStore.Save = ObserveSave
    PolicyEngine.Authorize = ObserveAuthorize
    summary = None
    exception = None
    plan = None

    try:
        plan = PlanNativeCrawl(root, "crawl", config["seed_url"], tuple(config["selected_urls"]),
            OWNER, lambda: Policy(config), limits=limits, current_owner_provider=CurrentOwner)

        if negative == "owner-after-plan":
            actor = "actor:changed-after-plan"

        summary = asyncio.run(RunNativeCrawl(root, "crawl", config["seed_url"],
            tuple(config["selected_urls"]), OWNER, lambda: Policy(config),
            approve_safe_crawl=config.get("approve", True), limits=limits,
            current_owner_provider=CurrentOwner))

    except (PermissionError, ValueError) as error:
        exception = type(error).__name__

    finally:
        LocalExecutor.Execute = original_execute
        LocalModelStore.Save = original_save
        PolicyEngine.Authorize = original_authorize

    identities = () if summary is None else tuple(item.evidence_id for item in summary.records)
    evidence = LocalEvidenceStore(root / "evidence")
    adapter = NativeCrawlAdapter(evidence.Read)

    return {"summary": None if summary is None else summary.ToDict(),
        "plan": None if plan is None else plan.ToDict(), "exception_type": exception,
        "executions": executions, "actual_model_saves": saves, "state": Inspect(root, identities),
        "capability": Detached(adapter.Descriptor), "health": Detached(adapter.CheckHealth())}


def Git(config: dict) -> dict:
    """Explicitly plan and separately confirm the unchanged actual STANDARD Git checker."""

    root = Path(config["workspace"])
    target = Target(TargetKind.URL, config["git_url"])
    plan = PlanNativeWebScan(root, "git-check", target, OWNER, lambda: Policy(config, git=True))
    confirmation = None if config.get("confirm") is False else PolicyConfirmation(
        plan.policy_plan.intent_sha256, "approval:separate-native-git")
    summary = asyncio.run(RunNativeWebScan(root, "git-check", target, OWNER,
        lambda: Policy(config, git=True), confirmation=confirmation))

    return {"summary": summary.ToDict(), "plan": plan.ToDict(), "state": Inspect(root)}


def Triage(config: dict) -> dict:
    """Persist one real operator disposition through the existing finding lifecycle and CAS
    owner."""

    root = Path(config["workspace"])
    store = LocalModelStore(root)
    model = store.Open()
    finding = next(item for item in Findings(model) if item.check_id == "native.git-head-exposure")
    provenance = replace(finding.provenance[0], source_id="operator.triage",
        run_reference="decision:independent-crawl-triage",
        observed_at=datetime.now(UTC).isoformat())
    proposed, _ = TransitionFinding(model, finding.ToObject(WORKSPACE_ID).Reference(),
        FindingStatus.CONFIRMED, provenance, "Independent operator disposition must survive rerun")
    store.Save(proposed, expected_revision=model.revision)

    return {"state": Inspect(root)}


def Main() -> int:
    """Execute one fixed consumer operation and emit genuine results without acceptance
    fabrication."""

    mode, config_path = sys.argv[1:]
    config = json.loads(Path(config_path).read_bytes())
    root = Path(config["workspace"])

    if mode == "setup":
        output = Setup(config)

    elif mode == "crawl":
        output = Crawl(config)

    elif mode == "git":
        output = Git(config)

    elif mode == "triage":
        output = Triage(config)

    elif mode == "inspect":
        output = {"state": Inspect(root), "reopen": OpenWorkspace(root)}

    else:
        raise ValueError("Unknown fixed independent consumer operation")

    output["installed_module"] = fuzzy1337.__file__
    output["installed_python"] = sys.executable
    sys.stdout.buffer.write(json.dumps(output, sort_keys=True, separators=(",", ":"),
                                      ensure_ascii=True, allow_nan=False).encode("ascii"))

    return 0


if __name__ == "__main__":
    raise SystemExit(Main())
