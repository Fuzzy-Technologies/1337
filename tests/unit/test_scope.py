# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Offline literal, consent, deny-precedence, and owned scope storage failure boundaries."""

from __future__ import annotations

import json
import os
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timezone
from pathlib import Path
from threading import Event

import pytest

from fuzzy1337 import scope
from fuzzy1337.scope import (
    MAX_SCOPE_BYTES,
    AuthorizationState,
    LocalScopeStore,
    ScopeAuthorization,
    ScopeBusyError,
    ScopeConflictError,
    ScopeDecision,
    ScopeDecisionReason,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration

DECISION_TIME = datetime(2026, 10, 5, tzinfo=timezone.utc)


def GrantedAuthorization() -> ScopeAuthorization:
    """Record bounded synthetic consent references without executable authority."""

    return ScopeAuthorization(
        AuthorizationState.GRANTED, "operator:fixture", "consent:fixture",
        "2026-10-01T00:00:00+00:00", "2026-11-01T00:00:00+00:00",
    )


def CreateStore(tmp_path: Path) -> tuple[LocalScopeStore, ScopeSnapshot]:
    """Create a real isolated workspace and one registered authorized scope."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Synthetic"), "synthetic")
    store = LocalScopeStore(root)
    target = Target(TargetKind.DOMAIN, "example.test")
    snapshot = ScopeSnapshot(
        "testing", "synthetic", GrantedAuthorization(), targets=(target,), allow=(target,)
    )
    store.Create(snapshot)

    return store, snapshot


def RecordPath(store: LocalScopeStore) -> Path:
    """Return one known fixture record path without using private product helpers."""

    return store.workspace_root / "state" / "scopes" / "testing.json"


@pytest.mark.parametrize("kind,value,expected", [
    (TargetKind.DOMAIN, "EXAMPLE.Test.", "example.test"),
    (TargetKind.DOMAIN, "bücher.test", "xn--bcher-kva.test"),
    (TargetKind.DOMAIN, "localhost", "localhost"),
    (TargetKind.IP, "2001:0DB8:0000::1", "2001:db8::1"),
    (TargetKind.IP, "192.0.2.1", "192.0.2.1"),
    (TargetKind.NETWORK, "2001:DB8::/32", "2001:db8::/32"),
    (TargetKind.NETWORK, "192.0.2.0/255.255.255.0", "192.0.2.0/24"),
    (TargetKind.URL, "HTTPS://BÜCHER.test.:443", "https://xn--bcher-kva.test/"),
    (TargetKind.URL, "http://192.0.2.1:80/a?q=1", "http://192.0.2.1/a?q=1"),
    (TargetKind.URL, "https://[2001:0DB8::1]:8443/a", "https://[2001:db8::1]:8443/a"),
    (TargetKind.URL, "http://example.test/é?q=中", "http://example.test/%C3%A9?q=%E4%B8%AD"),
    (TargetKind.URL, "http://example.test/%af?q=%ab", "http://example.test/%AF?q=%AB"),
])
def test_TargetNormalizationIsDeterministicAndTyped(kind, value, expected):
    """Equivalent explicit spellings yield one frozen canonical literal and reference."""

    target = Target(kind, value)

    assert target.value == expected, "Normalization changed the expected literal boundary"
    assert target.Reference() == Target(kind, expected).Reference(), "Identity differs by spelling"
    assert Target.FromDict(target.ToDict()) == target, "Typed canonical target did not round trip"

    with pytest.raises(FrozenInstanceError):
        target.value = "changed"


@pytest.mark.parametrize("kind,value", [
    ("domain", "example.test"), (None, "example.test"), (TargetKind.DOMAIN, None),
    (TargetKind.DOMAIN, ""), (TargetKind.DOMAIN, "example test"),
    (TargetKind.DOMAIN, "example.test\t"), (TargetKind.DOMAIN, "x\x7f.test"),
    (TargetKind.DOMAIN, "example..test"), (TargetKind.DOMAIN, "*.example.test"),
    (TargetKind.DOMAIN, "-example.test"), (TargetKind.DOMAIN, "example_.test"),
    (TargetKind.DOMAIN, "192.0.2.1"), (TargetKind.DOMAIN, "a" * 64 + ".test"),
    (TargetKind.DOMAIN, "0x7f000001"), (TargetKind.DOMAIN, "0x7f.0.0.1"),
    (TargetKind.DOMAIN, ".".join(["a" * 63] * 5)),
    (TargetKind.IP, "192.0.02.1"), (TargetKind.IP, "127.1"),
    (TargetKind.IP, "fe80::1%eth0"), (TargetKind.NETWORK, "fe80::%eth0/64"),
    (TargetKind.NETWORK, "192.0.2.1/24"), (TargetKind.NETWORK, "192.0.2.1"),
    (TargetKind.URL, "file:///outside"), (TargetKind.URL, "http:///path"),
    (TargetKind.URL, "http://operator@example.test/"),
    (TargetKind.URL, "http://operator:secret@example.test/"),
    (TargetKind.URL, "http://example.test/#fragment"),
    (TargetKind.URL, "http://example.test/#"),
    (TargetKind.URL, "http://example.test:0/"),
    (TargetKind.URL, "http://example.test:65536/"),
    (TargetKind.URL, "http://example.test:/"),
    (TargetKind.URL, "http://[malformed]/"),
    (TargetKind.URL, "http://0x7f000001/"), (TargetKind.URL, "http://0177.0.0.1/"),
    (TargetKind.URL, "http://[fe80::1%25eth0]/"),
    (TargetKind.URL, "http://example.test/a\\b"),
    (TargetKind.URL, "http://example.test/a/../b"),
    (TargetKind.URL, "http://example.test/a/%2e%2e/b"),
    (TargetKind.URL, "http://example.test//b"),
    (TargetKind.URL, "http://example.test/a%2fb"),
    (TargetKind.URL, "http://example.test/a%5cb"),
    (TargetKind.URL, "http://example.test/%wrong"),
    (TargetKind.URL, "http://example.test/" + "x" * 4096),
])
def test_TargetRejectsAmbiguousOrImplicitAddressing(kind, value):
    """Reject wildcard, credentials, redirects, ambiguous paths, and implicit host-bit widening."""

    with pytest.raises(ValueError):
        Target(kind, value)


@pytest.mark.parametrize("document", [
    [], {"kind": "domain", "value": "EXAMPLE.test"},
    {"kind": "ip", "value": "192.0.2.1", "extra": True},
    {"kind": "unknown", "value": "example.test"},
    {"kind": "ip"}, {"kind": False, "value": "192.0.2.1"},
])
def test_TargetDecoderRejectsUnknownAndNoncanonicalFields(document):
    """Persisted identities cannot be repaired or inferred while opening authoritative state."""

    with pytest.raises(ValueError):
        Target.FromDict(document)


@pytest.mark.parametrize("arguments", [
    {"state": "granted"}, {"state": AuthorizationState.GRANTED},
    {"state": AuthorizationState.GRANTED, "authority_reference": "operator:fixture"},
    {"authority_reference": "bad\nreference"}, {"record_reference": 1},
    {"valid_from": "2026-10-01"}, {"valid_until": False},
    {"valid_from": "invalid"},
    {"valid_from": "2026-11-01T00:00:00Z", "valid_until": "2026-10-01T00:00:00Z"},
])
def test_AuthorizationRejectsImplicitConsentAndInvalidValidity(arguments):
    """Granted consent needs references; validity must use an explicit timezone."""

    with pytest.raises(ValueError):
        ScopeAuthorization(**arguments)


def test_AuthorizationNormalizesUtcWithoutInferringConsent():
    """Normalize offsets, preserve explicit absence, and reject silent persisted-time repairs."""

    authorization = ScopeAuthorization(valid_from="2026-10-01T03:00:00+03:00")

    assert authorization.valid_from == "2026-10-01T00:00:00+00:00", "UTC normalization is incorrect"
    assert ScopeAuthorization.FromDict(authorization.ToDict()) == authorization
    document = authorization.ToDict()
    document["valid_from"] = "2026-10-01T00:00:00Z"

    with pytest.raises(ValueError, match="canonical"):
        ScopeAuthorization.FromDict(document)


@pytest.mark.parametrize("mutation", ["unknown", "missing", "enum", "reference"])
def test_AuthorizationDecoderRejectsMalformedMetadata(mutation):
    """Exact consent metadata cannot hide absent fields or unknown authorization states."""

    document = GrantedAuthorization().ToDict()

    if mutation == "unknown":
        document["extra"] = True

    elif mutation == "missing":
        del document["record_reference"]

    elif mutation == "enum":
        document["state"] = "assumed"

    else:
        document["authority_reference"] = False

    with pytest.raises(ValueError):
        ScopeAuthorization.FromDict(document)


@pytest.mark.parametrize("authorization,reason", [
    (ScopeAuthorization(), ScopeDecisionReason.AUTHORIZATION_UNKNOWN),
    (ScopeAuthorization(AuthorizationState.REVOKED), ScopeDecisionReason.AUTHORIZATION_REVOKED),
    (ScopeAuthorization(AuthorizationState.GRANTED, "operator:a", "consent:a",
                        valid_from="2026-10-06T00:00:00Z"),
     ScopeDecisionReason.AUTHORIZATION_NOT_YET_VALID),
    (ScopeAuthorization(AuthorizationState.GRANTED, "operator:a", "consent:a",
                        valid_until="2026-10-05T00:00:00Z"),
     ScopeDecisionReason.AUTHORIZATION_EXPIRED),
])
def test_AuthorizationDenialsPrecedeAnAllowRule(authorization, reason):
    """Missing, revoked, future, and expired consent override registered allowed targets."""

    target = Target(TargetKind.DOMAIN, "example.test")
    snapshot = ScopeSnapshot(
        "testing", "synthetic", authorization, targets=(target,), allow=(target,)
    )
    decision = snapshot.Check(target, at=DECISION_TIME)

    assert decision.reason == reason, "An allow rule bypassed consent state or validity"
    assert not decision.Allowed(), "A denied decision reported allowed membership"
    assert decision.rule_reference is None, "Consent denial pretended a membership rule matched"


def test_RegistrationDoesNotGrantMembershipAndIsIdempotent():
    """Registration proposes frozen state; allow rules do not implicitly register discoveries."""

    target = Target(TargetKind.DOMAIN, "example.test")
    snapshot = ScopeSnapshot("testing", "synthetic", GrantedAuthorization(), allow=(target,))

    assert snapshot.Check(target, at=DECISION_TIME).reason == ScopeDecisionReason.UNREGISTERED
    registered = snapshot.Register(target)

    assert registered.Register(target) is registered, "Repeat registration duplicated identity"
    assert registered.Check(target, at=DECISION_TIME).Allowed(), "Allowed target was denied"
    assert registered.revision == snapshot.revision, "Pure registration mutated persisted revision"
    assert snapshot.targets == (), "Registration mutated the prior immutable snapshot"
    assert replace(registered, allow=()).Check(target, at=DECISION_TIME).reason == (
        ScopeDecisionReason.NOT_ALLOWED
    ), "Registration granted membership without an allow rule"

    with pytest.raises(ValueError):
        snapshot.Register("example.test")


@pytest.mark.parametrize("deny,exclusions,reason", [
    (True, False, ScopeDecisionReason.DENIED),
    (False, True, ScopeDecisionReason.EXCLUDED),
    (True, True, ScopeDecisionReason.EXCLUDED),
])
def test_ExclusionAndDenyRulesPrecedeAllow(deny, exclusions, reason):
    """More restrictive explicit declarations always win, independently of allow-list order."""

    target = Target(TargetKind.IP, "192.0.2.3")
    network = Target(TargetKind.NETWORK, "192.0.2.0/24")
    snapshot = ScopeSnapshot(
        "testing", "synthetic", GrantedAuthorization(), targets=(target,), allow=(network,),
        deny=(target,) if deny else (), exclusions=(target,) if exclusions else (),
    )
    decision = snapshot.Check(target, at=DECISION_TIME)

    assert decision.reason == reason, "Allow bypassed a more restrictive explicit rule"
    assert decision.rule_reference == target.Reference(), "Decision lost its restrictive rule"


@pytest.mark.parametrize("rule_kind,rule_value,target_kind,target_value,allowed", [
    (TargetKind.DOMAIN, "example.test", TargetKind.DOMAIN, "sub.example.test", False),
    (TargetKind.DOMAIN, "example.test", TargetKind.URL, "http://example.test/", False),
    (TargetKind.URL, "http://example.test/a", TargetKind.URL, "http://example.test/a/b", False),
    (TargetKind.URL, "http://example.test/a", TargetKind.URL, "http://example.test/a?q=1", False),
    (TargetKind.URL, "http://example.test/a", TargetKind.URL, "https://example.test/a", False),
    (TargetKind.NETWORK, "192.0.2.0/24", TargetKind.IP, "192.0.2.1", True),
    (TargetKind.NETWORK, "192.0.2.0/24", TargetKind.IP, "192.0.3.1", False),
    (TargetKind.NETWORK, "192.0.2.0/24", TargetKind.NETWORK, "192.0.2.0/25", True),
    (TargetKind.NETWORK, "192.0.2.0/25", TargetKind.NETWORK, "192.0.2.0/24", False),
    (TargetKind.NETWORK, "2001:db8::/32", TargetKind.IP, "2001:db8::1", True),
    (TargetKind.NETWORK, "2001:db8::/32", TargetKind.IP, "192.0.2.1", False),
    (TargetKind.NETWORK, "2001:db8::/32", TargetKind.NETWORK, "192.0.2.0/24", False),
    (TargetKind.IP, "192.0.2.1", TargetKind.NETWORK, "192.0.2.1/32", False),
])
def test_RulesNeverInferDnsRedirectSubdomainOrPartialNetworkAuthority(
    rule_kind, rule_value, target_kind, target_value, allowed
):
    """Pure literal rules require exact domains/URLs or full same-version CIDR containment."""

    target = Target(target_kind, target_value)
    rule = Target(rule_kind, rule_value)
    snapshot = ScopeSnapshot("testing", "synthetic", GrantedAuthorization(),
                             targets=(target,), allow=(rule,))

    assert snapshot.Check(target, at=DECISION_TIME).Allowed() == allowed, "Typed rule overexpanded"


@pytest.mark.parametrize("kind,value", [
    (TargetKind.IP, "192.0.2.5"), (TargetKind.NETWORK, "192.0.2.0/25"),
    (TargetKind.NETWORK, "192.0.2.0/24"), (TargetKind.NETWORK, "192.0.0.0/16"),
])
def test_DeniedAddressOverlapRejectsWholeNetworkCandidates(kind, value):
    """An allowed broad scan cannot include any explicitly denied host or overlapping subnet."""

    candidate = Target(TargetKind.NETWORK, "192.0.2.0/24")
    rule = Target(kind, value)
    snapshot = ScopeSnapshot("testing", "synthetic", GrantedAuthorization(),
                             targets=(candidate,), allow=(candidate,), deny=(rule,))

    assert snapshot.Check(candidate, at=DECISION_TIME).reason == ScopeDecisionReason.DENIED


@pytest.mark.parametrize("rule_kind,rule_value,url", [
    (TargetKind.IP, "127.0.0.1", "http://127.0.0.1/"),
    (TargetKind.NETWORK, "127.0.0.0/8", "http://127.0.0.1:8080/path"),
    (TargetKind.IP, "2001:db8::1", "https://[2001:db8::1]/path"),
    (TargetKind.NETWORK, "2001:db8::/32", "https://[2001:db8::1]:8443/path"),
    (TargetKind.DOMAIN, "example.test", "https://example.test/path?q=1"),
    (TargetKind.DOMAIN, "BÜCHER.test", "https://xn--bcher-kva.test/"),
])
@pytest.mark.parametrize("field_name,reason", [
    ("deny", ScopeDecisionReason.DENIED), ("exclusions", ScopeDecisionReason.EXCLUDED),
])
def test_DeniedExplicitUrlAuthorityOverridesAnExactUrlAllowRule(
    rule_kind, rule_value, url, field_name, reason
):
    """Allowing a URL cannot bypass its already-known denied literal IP or canonical domain."""

    candidate = Target(TargetKind.URL, url)
    rule = Target(rule_kind, rule_value)
    snapshot = ScopeSnapshot(
        "testing", "synthetic", GrantedAuthorization(), targets=(candidate,), allow=(candidate,)
    )
    snapshot = replace(snapshot, **{field_name: (rule,)})
    decision = snapshot.Check(candidate, at=DECISION_TIME)

    assert decision.reason == reason, "Exact URL allow bypassed its denied authority"
    assert decision.rule_reference == rule.Reference(), "Projected denial lost its original rule"


@pytest.mark.parametrize("rule_kind,rule_value,url", [
    (TargetKind.IP, "127.0.0.1", "http://localhost/"),
    (TargetKind.DOMAIN, "localhost", "http://127.0.0.1/"),
    (TargetKind.DOMAIN, "example.test", "http://sub.example.test/"),
    (TargetKind.NETWORK, "2001:db8::/32", "http://192.0.2.1/"),
    (TargetKind.NETWORK, "192.0.2.0/24", "http://[2001:db8::1]/"),
])
def test_UrlAuthorityDenialDoesNotInferDnsSubdomainsOrAddressFamilies(rule_kind, rule_value, url):
    """Conservative denial reads literal authority only and performs no resolver inference."""

    candidate = Target(TargetKind.URL, url)
    snapshot = ScopeSnapshot(
        "testing", "synthetic", GrantedAuthorization(), targets=(candidate,), allow=(candidate,),
        deny=(Target(rule_kind, rule_value),),
    )

    assert snapshot.Check(candidate, at=DECISION_TIME).Allowed(), "Denial inferred an unknown alias"


def test_TargetAndScopeOperationsNeverConsultDnsOrConnect(monkeypatch):
    """Registration and decisions stay pure when every resolver/connection entry point fails."""

    def RejectNetwork(*arguments, **keywords):
        """Turn any accidental resolver lookup or connection into a direct test failure."""

        raise AssertionError("Scope operation attempted network access")

    for name in ("getaddrinfo", "gethostbyname", "gethostbyname_ex", "create_connection"):
        monkeypatch.setattr(socket, name, RejectNetwork)

    target = Target(TargetKind.URL, "https://BÜCHER.test/path")
    snapshot = ScopeSnapshot(
        "testing", "synthetic", GrantedAuthorization(), allow=(target,),
        deny=(Target(TargetKind.DOMAIN, "xn--bcher-kva.test"),),
    ).Register(target)

    assert snapshot.Check(target, at=DECISION_TIME).reason == ScopeDecisionReason.DENIED, (
        "Pure canonical authority denial failed without DNS"
    )
    assert ScopeSnapshot.FromDict(snapshot.ToDict()) == snapshot, "Pure schema roundtrip failed"


@pytest.mark.parametrize("arguments", [
    {"scope_id": "../outside"}, {"workspace_id": "UPPER"}, {"revision": True},
    {"revision": -1}, {"authorization": {}}, {"targets": "all"}, {"allow": ({},)},
    {"deny": (Target(TargetKind.IP, "192.0.2.1"),) * 2},
])
def test_SnapshotRejectsImplicitMalformedOrDuplicateMetadata(arguments):
    """Validation prevents path syntax, wrong types, and duplicate normalized declarations."""

    base = {"scope_id": "testing", "workspace_id": "synthetic"}
    base.update(arguments)

    with pytest.raises(ValueError):
        ScopeSnapshot(**base)


@pytest.mark.parametrize("target,at", [
    ("example.test", DECISION_TIME), (Target(TargetKind.IP, "192.0.2.1"), datetime(2026, 10, 5)),
    (Target(TargetKind.IP, "192.0.2.1"), "2026-10-05T00:00:00Z"),
])
def test_DecisionRejectsImplicitTargetsAndClocks(target, at):
    """Consumers must choose a typed target and explicit timezone-aware decision time."""

    with pytest.raises(ValueError):
        ScopeSnapshot("testing", "synthetic").Check(target, at=at)


@pytest.mark.parametrize("arguments", [
    {"reason": "allowed"}, {"scope_reference": "bad\nreference"},
    {"target_reference": None}, {"rule_reference": False},
])
def test_DecisionMetadataRequiresTypedReasonsAndReferences(arguments):
    """Malformed reason/reference metadata cannot masquerade as a valid membership result."""

    base = {"reason": ScopeDecisionReason.NOT_ALLOWED,
            "scope_reference": "scope:testing", "target_reference": "target:fixture"}
    base.update(arguments)

    with pytest.raises(ValueError):
        ScopeDecision(**base)


@pytest.mark.parametrize("field_name,value", [
    ("schema_version", 2), ("schema_version", True), ("scope_id", "other"),
    ("workspace_id", "other"), ("revision", False), ("targets", {}),
    ("allow", [False]), ("authorization", None),
])
def test_OpenRejectsInvalidSchemaFieldsAndOwnerBinding(tmp_path, field_name, value):
    """Reject unsupported scope fields instead of weakening authorization during decode."""

    store, snapshot = CreateStore(tmp_path)
    document = snapshot.ToDict()
    document[field_name] = value
    RecordPath(store).write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError):
        store.Open("testing")


@pytest.mark.parametrize("mutation", ["unknown", "missing", "not-object"])
def test_OpenRejectsNonexactSchemaObjects(tmp_path, mutation):
    """Unrecognized authoritative state cannot silently gain schema defaults."""

    store, snapshot = CreateStore(tmp_path)
    document = snapshot.ToDict()

    if mutation == "unknown":
        document["extra"] = True

    elif mutation == "missing":
        del document["authorization"]

    else:
        document = []

    RecordPath(store).write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ValueError):
        store.Open("testing")


@pytest.mark.parametrize("payload", [
    b'{"revision":1,"revision":1}', b'{"revision":NaN}', b'{"revision":Infinity}',
    b"invalid-json", b"\xff", b"\xef\xbb\xbf{}", b"[" * 2000 + b"]" * 2000,
])
def test_OpenRejectsCorruptAndAmbiguousJson(tmp_path, payload):
    """Duplicate keys, nonstandard numbers, invalid encoding, and nesting fail closed."""

    store, _ = CreateStore(tmp_path)
    RecordPath(store).write_bytes(payload)

    with pytest.raises(ValueError):
        store.Open("testing")


def test_CreateSaveAndCompareAndSwapKeepScopeIdentity(tmp_path):
    """A valid save increments revision once and stale/foreign proposals cannot replace it."""

    store, initial = CreateStore(tmp_path)
    assert store.Open("testing") == initial, "Initial persisted scope did not round trip"
    committed = store.Save(initial.Register(Target(TargetKind.IP, "192.0.2.1")))

    assert committed.revision == 1, "Save did not advance revision exactly once"
    assert store.Open("testing") == committed, "Committed snapshot was not observable"

    for proposal in (initial, replace(committed, workspace_id="other")):
        with pytest.raises(ScopeConflictError):
            store.Save(proposal)

    with pytest.raises(ScopeConflictError, match="exists"):
        store.Create(initial)

    with pytest.raises(ScopeConflictError, match="initial revision"):
        store.Create(replace(initial, scope_id="another", revision=1))

    assert store.Open("testing") == committed, "Rejected writes changed authoritative state"
    assert not (RecordPath(store).parent / ".testing.write-lock").exists(), "Writer lock leaked"


def test_ConstructionAndOperationsRejectInvalidStorageRootsAndIdentifiers(tmp_path):
    """Store construction is inert and scope IDs cannot traverse outside their namespace."""

    root = tmp_path / "absent"
    store = LocalScopeStore(root)

    assert not root.exists(), "Constructing the store performed filesystem mutation"

    for unsafe_root in ("not-a-path", tmp_path / ".." / "outside", Path(tmp_path.anchor)):
        with pytest.raises(ValueError):
            LocalScopeStore(unsafe_root)

    for scope_id in ("../outside", "scope:testing", "UPPER", "testing/other"):
        with pytest.raises(ValueError):
            store.Open(scope_id)

    with pytest.raises(ValueError):
        store.Create({})

    with pytest.raises(ValueError):
        store.Save(None)


def test_AbandonedWriterLockFailsClosedWithoutStealingOrBlockingReads(tmp_path):
    """A stale lock is operator-owned recovery work; reads remain available."""

    store, snapshot = CreateStore(tmp_path)
    lock_path = RecordPath(store).parent / ".testing.write-lock"
    lock_path.mkdir()

    with pytest.raises(ScopeBusyError):
        store.Save(snapshot)

    assert lock_path.is_dir(), "Store stole an existing writer's lock"
    assert store.Open("testing") == snapshot, "Writer ownership incorrectly blocked reads"


def test_CompetingWritersCannotLoseAnUpdate(tmp_path, monkeypatch):
    """A real blocked first writer excludes a concurrent writer and commits its whole snapshot."""

    store, initial = CreateStore(tmp_path)
    entered = Event()
    release = Event()
    original_write = LocalScopeStore._Write

    def BlockedWrite(self, path, snapshot):
        """Keep the first writer inside its owned transaction until the test releases it."""

        entered.set()

        if not release.wait(timeout=5):
            raise AssertionError("The test did not release its writer")

        original_write(self, path, snapshot)

    monkeypatch.setattr(LocalScopeStore, "_Write", BlockedWrite)

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(store.Save, initial.Register(Target(TargetKind.IP, "192.0.2.1")))

        try:
            assert entered.wait(timeout=5), "First writer never reached its lock-owned write"

            with pytest.raises(ScopeBusyError):
                store.Save(initial.Register(Target(TargetKind.IP, "192.0.2.2")))

            assert store.Open("testing") == initial, "Reader saw an incomplete new snapshot"

        finally:
            release.set()

        committed = future.result(timeout=5)

    assert store.Open("testing") == committed, "Concurrent writer lost the first committed update"


@pytest.mark.parametrize("operation", ["fsync", "replace"])
def test_PrepublicationWriteFailurePreservesOldStateAndCleansResources(
    tmp_path, monkeypatch, operation
):
    """Before replacement, write failures preserve old state and clean private resources."""

    store, initial = CreateStore(tmp_path)

    def FailOperation(*arguments):
        """Simulate an ordinary filesystem failure without mutating external state."""

        raise OSError("synthetic write failure")

    monkeypatch.setattr(scope.os, operation, FailOperation)

    with pytest.raises(OSError, match="synthetic"):
        store.Save(initial)

    assert store.Open("testing") == initial, "Failed prepublication write replaced old state"
    assert sorted(path.name for path in RecordPath(store).parent.iterdir()) == ["testing.json"], (
        "Failed write leaked temporary files or writer locks"
    )


def test_PostpublicationSyncFailureRequiresReopenBeforeRetry(tmp_path, monkeypatch):
    """A failed directory sync reports failure even if the new atomic snapshot is visible."""

    store, initial = CreateStore(tmp_path)

    def FailSync(path):
        """Fail only the scope post-replacement directory synchronization."""

        raise OSError("synthetic directory sync failure")

    monkeypatch.setattr(scope, "SyncStorageDirectory", FailSync)

    with pytest.raises(OSError, match="sync"):
        store.Save(initial)

    assert store.Open("testing").revision == 1, "Caller cannot recover the already-replaced state"
    assert not (RecordPath(store).parent / ".testing.write-lock").exists(), "Failure leaked a lock"


def test_StateSizeBoundAppliesToBothReadsAndWrites(tmp_path):
    """Bound authoritative metadata without partially replacing the prior valid record."""

    store, initial = CreateStore(tmp_path)
    oversized = replace(initial, authorization=replace(
        initial.authorization, record_reference="x" * MAX_SCOPE_BYTES
    ))

    with pytest.raises(ValueError, match="size limit"):
        store.Save(oversized)

    assert store.Open("testing") == initial, "Oversized save damaged the prior record"
    RecordPath(store).write_bytes(b" " * (MAX_SCOPE_BYTES + 1))

    with pytest.raises(ValueError, match="size limit"):
        store.Open("testing")


@pytest.mark.parametrize("boundary", ["root", "state", "namespace", "record"])
def test_ObservedSymlinkBoundariesAreRejected(tmp_path, boundary):
    """Never follow links at workspace, owned directory, or scope record boundaries."""

    store, _ = CreateStore(tmp_path)
    selected = {
        "root": store.workspace_root, "state": store.workspace_root / "state",
        "namespace": RecordPath(store).parent, "record": RecordPath(store),
    }[boundary]
    original = tmp_path / "linked-original"
    selected.rename(original)

    try:
        selected.symlink_to(original, target_is_directory=boundary != "record")

    except OSError:
        pytest.skip("Creating symlinks requires platform privileges unavailable to this test")

    with pytest.raises(ValueError, match="links|reparse"):
        store.Open("testing")


@pytest.mark.parametrize("boundary", ["namespace", "record"])
def test_NonphysicalNamespaceAndNonregularRecordAreRejected(tmp_path, boundary):
    """A namespace file or record directory cannot be interpreted as valid authoritative scope."""

    store, _ = CreateStore(tmp_path)
    path = RecordPath(store)
    path.unlink()

    if boundary == "namespace":
        path.parent.rmdir()
        path.parent.write_bytes(b"not a directory")

    else:
        path.mkdir()

    with pytest.raises(ValueError, match="directories|regular"):
        store.Open("testing")


def test_HardLinkedAuthoritativeRecordsAreRejected(tmp_path):
    """A record aliased into another namespace is outside the owned-file contract."""

    store, _ = CreateStore(tmp_path)
    os.link(RecordPath(store), tmp_path / "external-alias")

    with pytest.raises(ValueError, match="hard links"):
        store.Open("testing")


def test_MissingScopeIsAnErrorAndCreateRestoresAbsentOwnedPartitions(tmp_path):
    """Scope ownership may initialize absent partitions; missing records are never defaulted."""

    root = tmp_path / "workspace"
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration("Synthetic"), "synthetic")
    (root / "state").rmdir()
    store = LocalScopeStore(root)

    with pytest.raises(FileNotFoundError):
        store.Open("missing")

    snapshot = ScopeSnapshot("testing", "synthetic")

    assert store.Create(snapshot) == snapshot, "Create did not initialize its missing partition"
    assert store.Open("testing") == snapshot, "Initialized scope could not be reopened"
