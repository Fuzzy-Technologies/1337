# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Deterministic in-memory fakes; these tests establish no original acquisition or store ACK."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from fuzzy1337 import native_response_header_workflow as workflow
from fuzzy1337.adapters import AdapterExecution, EvidenceReference, ExecutionState, ImpactLevel
from fuzzy1337.evidence import EvidenceProvenance, EvidenceRecord
from fuzzy1337.findings import ApplyFindings, FindingStatus, TransitionFinding
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
    SecurityObject,
)
from fuzzy1337.native_response_headers import NativeResponseHeaderError
from fuzzy1337.owned_response_custody import OwnedResponseReplay
from fuzzy1337.owned_response_workflow import OwnedResponseReplaySummary, SourceFact
from fuzzy1337.policy import CapabilityPermission, ImpactPolicy
from fuzzy1337.scope import (
    AuthorizationState,
    ScopeAuthorization,
    ScopeSnapshot,
    Target,
    TargetKind,
)
from fuzzy1337.workspace import WorkspaceConfiguration, WorkspaceState


class FakeOriginalEnvironment:
    """Labelled fake replay/store owners with controlled authority and persistence boundaries."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, *, present: bool = False) -> None:
        """Build synthetic typed records without sockets, capture or actual store operations."""

        self.root = Path('/unit-only-workspace')
        self.now = datetime(2026, 10, 24, 12, 0, tzinfo=timezone.utc)
        self.target = Target(TargetKind.URL, 'http://127.0.0.1:12345/zap-passive/missing')
        self.ip = Target(TargetKind.IP, '127.0.0.1')
        self.owner = 'operator:unit-only'
        self.policy = ImpactPolicy('unit-policy', permissions=(CapabilityPermission(
            workflow.NATIVE_RESPONSE_CAPABILITY, workflow.NATIVE_RESPONSE_PROVIDER_ID,
            ImpactLevel.PASSIVE),), max_authorization_seconds=10)
        self.scope = ScopeSnapshot('unit-scope', 'unit-workspace', ScopeAuthorization(
            AuthorizationState.GRANTED, 'attester:separate', 'consent:unit',
            valid_until=(self.now + timedelta(seconds=20)).isoformat()),
            targets=(self.target, self.ip), allow=(self.target, self.ip))
        self.headers = b'HTTP/1.1 200 OK\r\nContent-Length: 1\r\n' + (
            b'X-Content-Type-Options: nosniff\r\n' if present else b'') + b'\r\n'
        self.content = {'stdout': b'fake-only-record', 'stderr': b'',
            'owned-response-request': b'fake-only-request', 'owned-response-headers': self.headers,
            'owned-response-body': b'x', 'owned-response-wire': self.headers + b'x',
            'owned-response-receipt': b'fake-only-receipt'}
        original = EvidenceProvenance('unit-workspace', 'scope:unit-scope',
            'native.loopback-response', '1', '1', self.now.isoformat(), self.now.isoformat(),
            execution=AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.1))
        records = []

        for role, raw in self.content.items():
            digest = hashlib.sha256(raw).hexdigest()
            media = 'application/json' if role in ('stdout', 'owned-response-receipt') else (
                'text/html; charset=utf-8' if role == 'owned-response-body' else
                'application/octet-stream')
            records.append(EvidenceRecord(EvidenceReference(role, 'blobs/sha256/' + digest,
                digest, media, len(raw)), original))

        self.records = tuple(records)
        self.receipt_id = records[-1].evidence_id
        self.record = {'outcome': 'captured', 'url': self.target.value,
            'catalog_sha256': '0' * 64, 'case_id': 'unit-only',
            'request': {'sha256': '1' * 64}, 'response': {'sha256': '2' * 64},
            'response_headers': {'size_bytes': len(self.headers),
                'sha256': hashlib.sha256(self.headers).hexdigest()},
            'response_body': {'size_bytes': 1}}
        self.fact = SourceFact('unit-workspace', self.record, self.records, self.receipt_id,
            'job:unit-only')
        endpoint = SecurityObject(ObjectIdentity('unit-workspace', ObjectKind.ENDPOINT,
            self.target.value), {}, (self.fact.provenance,))
        self.model = ModelState('unit-workspace', revision=2,
            objects=(endpoint,), observations=(self.fact,))
        self.workspace = WorkspaceState('unit-workspace', WorkspaceConfiguration('Unit only'),
            revision=3, scope_references=('scope:unit-scope',),
            object_references=(endpoint.Reference(),), job_references=('job:unit-only',),
            evidence_references=tuple(item.reference for item in self.records),
            evidence_record_references=tuple(item.evidence_id for item in self.records))
        self.model_saves = self.workspace_saves = self.source_reads = 0
        self.on_read = self.on_composition = self.on_model_save = self.on_workspace_save = None
        self.on_product = self.on_custody = self.on_get = None
        self.model_ack = self.workspace_ack = 'return'
        self.open_model_error = self.open_workspace_error = False
        environment = self

        class FakeModelStore:
            """In-memory CAS fake, never canonical durable persistence."""

            def __init__(self, root):
                """Retain the selected fake workspace boundary without I/O."""

                self.root = root

            def Open(self):
                """Return controlled model metadata or an injected read failure."""

                if environment.open_model_error:
                    raise OSError('unit-only')

                return environment.model

            def Save(self, state, *, expected_revision):
                """Apply one fake CAS and independently control its returned ACK."""

                environment.model_saves += 1
                assert expected_revision == environment.model.revision, 'Keep original CAS basis'

                if environment.model_ack == 'refuse':
                    raise OSError('unit-only refusal')

                environment.model = state

                if environment.on_model_save is not None:
                    environment.on_model_save()

                if environment.model_ack == 'lost':
                    raise OSError('unit-only lost ACK')

                return state if environment.model_ack == 'return' else replace(state,
                    revision=state.revision + 1)

        class FakeWorkspaceStore:
            """In-memory separate revision owner, never a genuine Save ACK."""

            def __init__(self, root):
                """Retain the selected fake workspace boundary without I/O."""

                self.root = root

            def Open(self):
                """Return controlled workspace metadata or an injected read failure."""

                if environment.open_workspace_error:
                    raise OSError('unit-only')

                return environment.workspace

            def Save(self, state):
                """Apply one fake reference transition and independently control its ACK."""

                environment.workspace_saves += 1
                assert state.revision == environment.workspace.revision, 'Keep original CAS basis'

                if environment.workspace_ack == 'refuse':
                    raise OSError('unit-only refusal')

                environment.workspace = replace(state, revision=state.revision + 1)

                if environment.on_workspace_save is not None:
                    environment.on_workspace_save()

                if environment.workspace_ack == 'lost':
                    raise OSError('unit-only lost ACK')

                return environment.workspace if environment.workspace_ack == 'return' else state

        class FakeScopeStore:
            """Fresh controlled scope reader, independent of actor attribution."""

            def __init__(self, root):
                """Retain the selected fake workspace boundary without I/O."""

                self.root = root

            def Open(self, scope_id):
                """Read the currently controlled scope and independent attester."""

                assert scope_id == 'unit-scope', 'Read selected existing scope'

                return environment.scope

        class FakeEvidenceStore:
            """Typed original-reference fake; no Put method exists."""

            def __init__(self, root):
                """Retain the selected fake workspace boundary without I/O."""

                self.root = root

            def Get(self, identity):
                """Resolve only a selected fake manifest ID."""

                if environment.on_get is not None:
                    environment.on_get()

                return next(item for item in environment.records if item.evidence_id == identity)

            def Read(self, reference):
                """Return fake selected role bytes through a controllable boundary."""

                environment.source_reads += 1

                if environment.on_read is not None:
                    environment.on_read()

                return environment.content[reference.role]

        def Product(root, receipt_id):
            """Return labelled fake product association metadata."""

            if environment.on_product is not None:
                environment.on_product()

            return OwnedResponseReplaySummary('job:unit-only', receipt_id, environment.records,
                json.loads(CanonicalModelJson(environment.fact.attributes)),
                environment.model.revision, environment.workspace.revision)

        def Custody(store, receipt_id):
            """Return labelled fake complete-custody metadata without acquiring bytes."""

            if environment.on_custody is not None:
                environment.on_custody()

            return OwnedResponseReplay(b'unit-only', receipt_id,
                tuple(item.evidence_id for item in environment.records[:-1]))

        def Compose(model, findings, root):
            """Use the real pure model fold after explicitly faked evidence verification."""

            result = ApplyFindings(model, findings)

            if environment.on_composition is not None:
                environment.on_composition()

            return result

        monkeypatch.setattr(workflow, 'LocalModelStore', FakeModelStore)
        monkeypatch.setattr(workflow, 'LocalWorkspaceStore', FakeWorkspaceStore)
        monkeypatch.setattr(workflow, 'LocalScopeStore', FakeScopeStore)
        monkeypatch.setattr(workflow, 'OwnedResponseEvidenceStore', FakeEvidenceStore)
        monkeypatch.setattr(workflow, 'ReplayOwnedResponse', Product)
        monkeypatch.setattr(workflow, 'ReplayOwnedResponseCapture', Custody)
        monkeypatch.setattr(workflow, 'ParseOwnedResponseCapture', lambda raw, url: self.record)
        monkeypatch.setattr(workflow, 'ApplyVerifiedFindings', Compose)

    def Apply(self, **overrides):
        """Call actual SDK orchestration over explicit deterministic fake owners."""

        arguments = {'analysis_reference': 'analysis:unit-only',
            'expected_model_revision': self.model.revision,
            'expected_workspace_revision': self.workspace.revision,
            'approve_passive_header_check': True, 'current_owner_provider': lambda: self.owner,
            'clock': lambda: self.now}
        arguments.update(overrides)

        return workflow.ApplyOwnedResponseHeaderCheck(self.root, 'unit-scope', self.receipt_id,
            self.target, 'operator:unit-only', lambda: self.policy, **arguments)

    def Replay(self, summary):
        """Verify actual retained model observation over labelled fake source owners."""

        return workflow.ReplayOwnedResponseHeaderCheck(self.root, summary.assessment_reference)

    def Advance(self, seconds=10):
        """Move controlled receiver time without sleeping or renewing authority."""

        self.now += timedelta(seconds=seconds)


@pytest.mark.parametrize('present', [False, True])
def test_OneAttemptAndHistoricalReplay(monkeypatch, present):
    """Actual orchestration uses seven refs, execution absent and conditional reference Save."""

    environment = FakeOriginalEnvironment(monkeypatch, present=present)
    summary = environment.Apply()
    assert summary.state == 'completed', summary.ToDict()
    assert summary.condition_observed is not present, 'Observe actual header names'
    assert (environment.model_saves, environment.workspace_saves) == (1, int(not present)), (
        'At most one original-basis Save for each owner')
    assert summary.model_commit == 'acknowledged', 'Only exact fake return acknowledges'
    observation = next(item for item in environment.model.observations if
        item.Reference() == summary.assessment_reference)
    assert observation.provenance.execution is None, 'Offline interpretation has no execution'
    assert len(observation.provenance.evidence_references) == 7, 'Reuse all original references'
    assert len(observation.attributes['authority_basis']) == 21, 'Closed authority basis'
    environment.Advance(1000)
    replay = environment.Replay(summary)
    assert replay.ToDict()['state'] == 'verified', 'Historical expiry does not issue a new window'
    assert replay.condition_observed is not present, 'Recompute actual original header predicate'


def test_ExactReuseNeverSaves(monkeypatch):
    """A complete retained interpretation reuses its original attribution without re-Save."""

    environment = FakeOriginalEnvironment(monkeypatch)
    first = environment.Apply()
    original = environment.model
    result = environment.Apply()
    assert result.state == 'already-applied', result.ToDict()
    assert result.assessment_reference == first.assessment_reference, 'Keep original assessment'
    assert environment.model == original, 'No reattribution'
    assert (environment.model_saves, environment.workspace_saves) == (1, 1), 'No repeated Save'


@pytest.mark.parametrize('failure', ['approval', 'policy', 'owner', 'scope', 'excluded', 'ip'])
def test_CurrentAdmissionDeniesBeforeSource(monkeypatch, failure):
    """Separate opt-in, permission, actor, registration and exclusions fail before source reads."""

    environment = FakeOriginalEnvironment(monkeypatch)
    overrides = {}

    if failure == 'approval':
        overrides['approve_passive_header_check'] = False

    elif failure == 'policy':
        environment.policy = ImpactPolicy('unit-policy')

    elif failure == 'owner':
        environment.owner = 'operator:changed'

    elif failure == 'scope':
        environment.scope = replace(environment.scope, targets=(environment.ip,))

    elif failure == 'excluded':
        environment.scope = replace(environment.scope, exclusions=(environment.target,))

    else:
        environment.scope = replace(environment.scope, allow=(environment.target,))

    result = environment.Apply(**overrides)
    assert result.state == 'denied', result.ToDict()
    assert result.failure == 'authorization', 'Closed safe failure'
    assert environment.source_reads == environment.model_saves == 0, 'No source or mutation'
    assert result.condition_observed is None, 'No invented observation on refusal'


@pytest.mark.parametrize('boundary', ['read', 'composition', 'product', 'custody', 'get'])
@pytest.mark.parametrize('change', ['owner', 'scope', 'policy', 'expired', 'regression'])
def test_FreshBoundariesRefuseDriftAndLateReturn(monkeypatch, boundary, change):
    """Return-preserving fake boundaries expose current drift before interpretation or Save."""

    environment = FakeOriginalEnvironment(monkeypatch)

    def Change():
        """Change controlled authority or receiver time at the selected boundary."""

        if change == 'owner':
            environment.owner = 'operator:changed'

        elif change == 'scope':
            environment.scope = replace(environment.scope, revision=1)

        elif change == 'policy':
            environment.policy = replace(environment.policy, revision=1)

        elif change == 'expired':
            environment.Advance()

        else:
            environment.Advance(-1)

    setattr(environment, 'on_' + boundary, Change)
    result = environment.Apply()
    assert result.state == 'denied', result.ToDict()
    assert result.failure == {'expired': 'admission-expired',
        'regression': 'clock-regression'}.get(change, 'authorization'), 'Exact safe refusal'
    assert environment.model_saves == environment.workspace_saves == 0, 'No late Save'
    assert result.assessment_reference is result.condition_observed is None, 'No fabricated fact'


@pytest.mark.parametrize('owner', ['model', 'workspace'])
@pytest.mark.parametrize('ack', ['refuse', 'lost', 'wrong'])
def test_PersistenceAckAndPartialState(monkeypatch, owner, ack):
    """Observed state cannot upgrade a missing ACK and each store receives at most one Save."""

    environment = FakeOriginalEnvironment(monkeypatch)
    setattr(environment, owner + '_ack', ack)
    result = environment.Apply()
    assert result.state == ('failed' if owner == 'model' and ack == 'refuse' else 'partial'), (
        result.ToDict())
    assert result.failure == 'storage', 'Storage failure remains explicit'
    assert environment.model_saves == 1, 'One model Save attempt'
    assert environment.workspace_saves == int(owner == 'workspace'), 'No retry or blind repair'
    assert getattr(result, owner + '_commit') == (
        'observed-unchanged' if ack == 'refuse' else 'observed-committed'), 'Truthful observed ACK'
    assert (result.assessment_reference is None) is (owner == 'model' and ack == 'refuse'), (
        'Only actually retained assessment references are exposed')


def test_ExpiryAfterModelAckPreservesPartial(monkeypatch):
    """Late model Save return preserves its true ACK and prevents workspace retention."""

    environment = FakeOriginalEnvironment(monkeypatch)
    environment.on_model_save = environment.Advance
    result = environment.Apply()
    assert result.state == 'partial', result.ToDict()
    assert result.model_commit == 'acknowledged', 'Keep actual returned model ACK'
    assert result.workspace_commit == 'not-attempted', 'No expired reference Save'
    assert result.failure == 'admission-expired', 'Original window remains exclusive'
    assert result.finding_reference is not None, 'Expose actual partial model Finding'


def test_OriginalConsentExpiryWins(monkeypatch):
    """The fixed initial window uses the earlier consent expiry without renewal."""

    environment = FakeOriginalEnvironment(monkeypatch)
    environment.scope = replace(environment.scope, authorization=replace(
        environment.scope.authorization,
        valid_until=(environment.now + timedelta(seconds=2)).isoformat()))
    environment.on_read = lambda: environment.Advance(2)
    result = environment.Apply()
    assert result.failure == 'admission-expired', result.ToDict()
    assert environment.model_saves == 0, 'Late source read is not interpreted'


def test_SelectedAttributionIsNotAuthentication(monkeypatch):
    """Without a trusted reader, the recorded fact is only the explicitly selected operator."""

    environment = FakeOriginalEnvironment(monkeypatch)
    result = environment.Apply(current_owner_provider=None)
    observation = next(item for item in environment.model.observations if
        item.Reference() == result.assessment_reference)
    assert observation.attributes['authority_basis']['owner_attribution'] == 'selected', (
        'No external authentication claim')


@pytest.mark.parametrize('revision', ['model', 'workspace'])
def test_ExpectedRevisionConflictBeforeSource(monkeypatch, revision):
    """Caller CAS mismatch is not silently rebased."""

    environment = FakeOriginalEnvironment(monkeypatch)
    result = environment.Apply(**{'expected_' + revision + '_revision': 0})
    assert result.failure == 'revision-conflict', result.ToDict()
    assert environment.source_reads == environment.model_saves == 0, 'No new source or Save'


def test_ConcurrentBasisChangeRefuses(monkeypatch):
    """A concurrent writer between composition and final guard remains authoritative."""

    environment = FakeOriginalEnvironment(monkeypatch)
    environment.on_composition = lambda: setattr(environment, 'model', replace(
        environment.model, revision=environment.model.revision + 1))
    result = environment.Apply()
    assert result.failure == 'revision-conflict', result.ToDict()
    assert environment.model_saves == 0, 'No rebase or Save'


@pytest.mark.parametrize('broken', ['manifest', 'raw-reference', 'endpoint', 'job', 'scope',
    'provenance', 'refused', 'url', 'header-hash', 'header-size', 'header-bytes'])
def test_OriginalSourceJoinsFailClosed(monkeypatch, broken):
    """Synthetic fake corruption exercises explicit source joins without genuine admission."""

    environment = FakeOriginalEnvironment(monkeypatch)

    if broken == 'manifest':
        environment.workspace = replace(environment.workspace, evidence_record_references=())

    elif broken == 'raw-reference':
        environment.workspace = replace(environment.workspace, evidence_references=())

    elif broken == 'endpoint':
        environment.workspace = replace(environment.workspace, object_references=())

    elif broken == 'job':
        environment.workspace = replace(environment.workspace, job_references=())

    elif broken == 'scope':
        environment.records = tuple(replace(item, provenance=replace(item.provenance,
            scope_reference='scope:another')) for item in environment.records)

    elif broken == 'provenance':
        environment.records = (*environment.records[:-1], replace(environment.records[-1],
            provenance=replace(environment.records[-1].provenance, execution=None)))

    elif broken == 'refused':
        environment.record['outcome'] = 'refused'

    elif broken == 'url':
        environment.record['url'] = environment.target.value + '/different'

    elif broken == 'header-hash':
        environment.record['response_headers']['sha256'] = 'f' * 64

    elif broken == 'header-size':
        environment.record['response_headers']['size_bytes'] = True

    else:
        environment.content['owned-response-headers'] += b'bad'

    result = environment.Apply()
    assert result.state == 'failed', result.ToDict()
    assert result.failure == 'source', 'No source corruption becomes a clean result'
    assert result.condition_observed is None and environment.model_saves == 0, 'No fabricated fact'


def test_ReuseMissingRetentionIsPriorPartial(monkeypatch):
    """A new call does not repair an earlier partial reference commit or certify its replay."""

    environment = FakeOriginalEnvironment(monkeypatch)
    environment.workspace_ack = 'refuse'
    first = environment.Apply()
    second = environment.Apply()
    assert first.state == second.state == 'partial', (first.ToDict(), second.ToDict())
    assert (environment.model_saves, environment.workspace_saves) == (1, 1), 'No automatic repair'

    with pytest.raises(NativeResponseHeaderError, match='replay is unverified'):
        environment.Replay(first)


@pytest.mark.parametrize('edit', ['extra', 'basis-extra', 'bool-revision', 'hash', 'window',
    'owner-attribution', 'condition', 'source', 'execution'])
def test_HistoricalAssessmentTamperingRefuses(monkeypatch, edit):
    """Closed attributes, timing, source and honest provenance are independently checked."""

    environment = FakeOriginalEnvironment(monkeypatch)
    result = environment.Apply()
    original = next(item for item in environment.model.observations if
        item.Reference() == result.assessment_reference)
    attributes = json.loads(CanonicalModelJson(original.attributes))
    provenance = original.provenance

    if edit == 'extra':
        attributes['extra'] = True

    elif edit == 'basis-extra':
        attributes['authority_basis']['extra'] = True

    elif edit == 'bool-revision':
        attributes['authority_basis']['model_revision'] = True

    elif edit == 'hash':
        attributes['authority_basis']['scope_sha256'] = 'x' * 64

    elif edit == 'window':
        attributes['authority_basis']['expires_at'] = attributes['authority_basis']['checked_at']

    elif edit == 'owner-attribution':
        attributes['authority_basis']['owner_attribution'] = 'authenticated'

    elif edit == 'condition':
        attributes['condition_observed'] = False

    elif edit == 'source':
        attributes['header_sha256'] = '0' * 64

    else:
        provenance = replace(provenance, execution=AdapterExecution(ExecutionState.SUCCEEDED, 0, 0))

    modified = Observation(original.kind, original.subject_reference, attributes, provenance)
    environment.model = replace(environment.model, observations=tuple(
        modified if item == original else item for item in environment.model.observations))

    with pytest.raises(NativeResponseHeaderError, match='replay is unverified'):
        workflow.ReplayOwnedResponseHeaderCheck(environment.root, modified.Reference())


def test_ReplayAndReusePreserveTriage(monkeypatch):
    """Historical detection stays valid after valid triage and a new analysis preserves it."""

    environment = FakeOriginalEnvironment(monkeypatch)
    first = environment.Apply()
    environment.model, _ = TransitionFinding(environment.model, first.finding_reference,
        FindingStatus.CONFIRMED,
        next(item.provenance for item in environment.model.observations if
            item.Reference() == first.assessment_reference), 'unit-only confirmed')
    second = environment.Apply(analysis_reference='analysis:second')
    assert second.state == 'completed', second.ToDict()
    assert environment.workspace_saves == 1, 'Existing retained Finding needs no reference Save'
    assert environment.Replay(first).finding_reference == first.finding_reference, 'Keep detection'
    assert environment.Replay(second).finding_reference == first.finding_reference, (
        'Stable identity')


@pytest.mark.parametrize('overrides', [
    {'approve_passive_header_check': 1}, {'expected_model_revision': True},
    {'current_owner_provider': 'operator'}, {'clock': None}, {'analysis_reference': ''},
])
def test_MalformedConfigurationRaisesBeforeSource(monkeypatch, overrides):
    """Programming errors are distinct from well-typed denied or failed attempts."""

    environment = FakeOriginalEnvironment(monkeypatch)

    with pytest.raises(NativeResponseHeaderError, match='configuration is invalid'):
        environment.Apply(**overrides)

    assert environment.source_reads == environment.model_saves == 0, 'No source or mutation'


@pytest.mark.parametrize('boundary', ['model', 'workspace'])
@pytest.mark.parametrize('change', ['owner', 'scope', 'policy'])
def test_FinalClockMutationPrecedesFreshAuthorityBeforeEitherSave(
    monkeypatch, boundary, change,
):
    """A valid final clock callback can change authority without changing time or the window."""

    environment = FakeOriginalEnvironment(monkeypatch)
    original_check = workflow.HeaderAdmission.Check
    original_bases = workflow.HeaderAttempt.RequireBases
    state = {'after_bases': 0, 'boundary': None, 'inside': False, 'clocks': 0, 'changed': False}

    def Bases(self, model, workspace):
        """Select the exact model or conditional workspace final original-basis fence."""

        result = original_bases(self, model, workspace)
        state['boundary'] = 'model' if environment.model_saves == 0 else 'workspace'
        state['after_bases'] = 0

        return result

    def Check(self):
        """Arm the full explicit final Check after SourceCall's immediate post-read Check."""

        if state['boundary'] is not None:
            state['after_bases'] += 1

        state['inside'] = state['boundary'] == boundary and state['after_bases'] == 2
        state['clocks'] = 0

        try:
            return original_check(self)

        finally:
            state['inside'] = False

    def Clock():
        """Return unchanged valid time while changing authority in the final sampled callback."""

        if state['inside']:
            state['clocks'] += 1

            if state['clocks'] == 2 and not state['changed']:
                state['changed'] = True

                if change == 'owner':
                    environment.owner = 'operator:changed'

                elif change == 'scope':
                    environment.scope = replace(environment.scope, revision=1)

                else:
                    environment.policy = replace(environment.policy, revision=1)

        return environment.now

    monkeypatch.setattr(workflow.HeaderAttempt, 'RequireBases', Bases)
    monkeypatch.setattr(workflow.HeaderAdmission, 'Check', Check)
    summary = environment.Apply(clock=Clock)
    assert state['changed'], 'The actual final callback mutation must be reached, never skipped'
    assert environment.model_saves == int(boundary == 'workspace'), (
        'Final clock mutation must prevent the protected model Save or preserve only its prior ACK')
    assert environment.workspace_saves == 0, 'No conditional workspace Save follows authority drift'
    assert summary.failure == 'authorization', summary.ToDict()
    assert summary.state == ('denied' if boundary == 'model' else 'partial'), summary.ToDict()


def test_FinalFullAuthorityIsLastCallbackBoundaryBeforeBothSaves(monkeypatch):
    """Trace only labelled fake callback order, without genuine sources, SDK I/O or storage ACKs."""

    environment = FakeOriginalEnvironment(monkeypatch)
    trace = []
    original_scope = workflow.LocalScopeStore.Open

    def Scope(self, scope_id):
        """Record the fresh selected scope read without changing its actual fake value."""

        trace.append('scope')

        return original_scope(self, scope_id)

    def Policy():
        """Record the unchanged current typed policy reader."""

        trace.append('policy')

        return environment.policy

    def Owner():
        """Record the unchanged trusted current actor reader."""

        trace.append('owner')

        return environment.owner

    def Clock():
        """Record the unchanged valid aware admission-time callback."""

        trace.append('clock')

        return environment.now

    monkeypatch.setattr(workflow.LocalScopeStore, 'Open', Scope)
    environment.on_model_save = lambda: trace.append('model-save')
    environment.on_workspace_save = lambda: trace.append('workspace-save')
    result = workflow.ApplyOwnedResponseHeaderCheck(environment.root, 'unit-scope',
        environment.receipt_id, environment.target, environment.owner, Policy,
        analysis_reference='analysis:trace-only',
        expected_model_revision=environment.model.revision,
        expected_workspace_revision=environment.workspace.revision,
        approve_passive_header_check=True,
        current_owner_provider=Owner, clock=Clock)
    assert result.state == 'completed', result.ToDict()

    for event in ('model-save', 'workspace-save'):
        index = trace.index(event)
        assert trace[index - 3:index] == ['scope', 'policy', 'owner'], (
            'The final selected authority reads must follow every clock callback before Save')
        assert trace[index - 7:index] == ['scope', 'policy', 'owner', 'clock',
            'scope', 'policy', 'owner'], (
                'Fence consumed reader time before the final no-further-clock authority refresh')


@pytest.mark.parametrize('boundary', ['model', 'workspace'])
def test_FinalAuthorityReadTimeIsFencedBeforeEitherOriginalSave(monkeypatch, boundary):
    """An unchanged final policy read consuming the original TTL must refuse before its Save."""

    environment = FakeOriginalEnvironment(monkeypatch)
    issued = environment.now
    original_check = workflow.HeaderAdmission.Check
    original_bases = workflow.HeaderAttempt.RequireBases
    state = {'boundary': None, 'after_bases': 0, 'inside': False,
        'entered': False, 'advanced': False, 'window': None}
    save_times = []

    def Bases(self, model, workspace):
        """Select the actual final original-basis fence without touching any real store."""

        result = original_bases(self, model, workspace)
        state['boundary'] = 'model' if environment.model_saves == 0 else 'workspace'
        state['after_bases'] = 0

        return result

    def Check(self):
        """Arm only the final Check after SourceCall's required post-read admission Check."""

        if state['boundary'] is not None:
            state['after_bases'] += 1

        state['inside'] = state['boundary'] == boundary and state['after_bases'] == 2

        if state['inside']:
            state['window'] = self.issued, self.expires

        try:
            return original_check(self)

        finally:
            state['inside'] = False

    def Clock():
        """Reach AT+9 once at the selected final Check, then report actual controlled time."""

        if state['inside'] and not state['entered']:
            state['entered'] = True
            environment.now = issued + timedelta(seconds=9)

        return environment.now

    def Policy():
        """Keep the exact policy while its selected synchronous read consumes two fake seconds."""

        if state['inside'] and not state['advanced']:
            state['advanced'] = True
            environment.Advance(2)

        return environment.policy

    monkeypatch.setattr(workflow.HeaderAttempt, 'RequireBases', Bases)
    monkeypatch.setattr(workflow.HeaderAdmission, 'Check', Check)
    environment.on_model_save = lambda: save_times.append(('model', environment.now))
    environment.on_workspace_save = lambda: save_times.append(('workspace', environment.now))
    result = workflow.ApplyOwnedResponseHeaderCheck(environment.root, 'unit-scope',
        environment.receipt_id, environment.target, environment.owner, Policy,
        analysis_reference='analysis:final-reader-time',
        expected_model_revision=environment.model.revision,
        expected_workspace_revision=environment.workspace.revision,
        approve_passive_header_check=True, current_owner_provider=lambda: environment.owner,
        clock=Clock)
    assert state['entered'] and state['advanced'], 'Exercise actual final reader time consumption'
    assert state['window'] == (issued, issued + timedelta(seconds=10)), 'Keep original fixed window'
    assert environment.now == issued + timedelta(seconds=11), 'Reader returns after fixed expiry'
    assert environment.model_saves == int(boundary == 'workspace') and (
        environment.workspace_saves == 0
    ), (
        'Final unchanged-policy read expiry must precede either protected original Save')
    assert all(moment < issued + timedelta(seconds=10) for _, moment in save_times), (
        'No protected Save may occur after reader-consumed original expiry')
    assert result.failure == 'admission-expired', result.ToDict()
    assert result.state == ('denied' if boundary == 'model' else 'partial'), result.ToDict()
    assert result.model_commit == ('not-attempted' if boundary == 'model' else 'acknowledged'), (
        'Only an actually earlier model ACK survives workspace-boundary expiry')
    assert result.workspace_commit == 'not-attempted', 'No expired reference Save attempt'
