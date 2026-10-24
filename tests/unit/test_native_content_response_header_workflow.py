# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Explicit labelled fake source owners test strict header-v2 dispatch without capture or I/O."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest

from fuzzy1337 import native_response_header_workflow as workflow
from fuzzy1337.evidence import EvidenceRecord
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelProvenance,
    ObjectIdentity,
    ObjectKind,
    SecurityObject,
)
from fuzzy1337.native_response_headers import NativeResponseHeaderError
from fuzzy1337.owned_response_custody import _CATALOG_FAMILY, _CONTENT_FAMILY
from fuzzy1337.owned_response_workflow import OwnedResponseReplaySummary, SourceFact
from fuzzy1337.scope import Target, TargetKind
from tests.unit.test_native_response_header_workflow import FakeOriginalEnvironment


class FakeContentEnvironment(FakeOriginalEnvironment):
    """Reuse controlled owner boundaries while replacing all fake source-family attribution."""

    def __init__(self, monkeypatch, *, present=False):
        """Declare synthetic content facts explicitly; no original capture or ACK is claimed."""

        super().__init__(monkeypatch, present=present)
        self.target = Target(TargetKind.URL, 'http://127.0.0.1:12345/original/content')
        self.scope = replace(self.scope, targets=(self.target, self.ip),
                             allow=(self.target, self.ip))
        self.records = tuple(EvidenceRecord(replace(item.reference,
            media_type='application/octet-stream') if item.reference.role == (
                'owned-response-body') else item.reference,
            replace(item.provenance, source_id='native.loopback-content-response'))
            for item in self.records)
        self.receipt_id = self.records[-1].evidence_id
        self.record = {key: value for key, value in self.record.items()
                       if key not in ('case_id', 'catalog_sha256')}
        self.record.update(url=self.target.value, media_type='text/plain')
        self.fact = SourceFact('unit-workspace', self.record, self.records, self.receipt_id,
                               'job:unit-only', _family=_CONTENT_FAMILY)
        endpoint = SecurityObject(ObjectIdentity('unit-workspace', ObjectKind.ENDPOINT,
            self.target.value), {}, (self.fact.provenance,))
        self.model = replace(self.model, objects=(endpoint,), observations=(self.fact,))
        self.workspace = replace(self.workspace, object_references=(endpoint.Reference(),),
            evidence_references=tuple(item.reference for item in self.records),
            evidence_record_references=tuple(item.evidence_id for item in self.records))
        store_type = workflow.OwnedResponseEvidenceStore
        environment = self

        class FakeContentStore(store_type):
            """Require the explicit selected binding at the original labelled fake owner."""

            def __init__(self, root, *, _family=_CATALOG_FAMILY):
                """Record selected source dispatch rather than substituting an actual store."""

                environment.selected_family = _family
                super().__init__(root)

        def Product(root, receipt_id):
            """Return only controlled fake content association, never old replay fallback."""

            if environment.on_product is not None:
                environment.on_product()

            return OwnedResponseReplaySummary('job:unit-only', receipt_id, environment.records,
                json.loads(CanonicalModelJson(environment.fact.attributes)),
                environment.model.revision, environment.workspace.revision, _CONTENT_FAMILY)

        def Parse(raw, url, family):
            """Require exact selected content parser route at a labelled fake byte boundary."""

            assert family is _CONTENT_FAMILY and url == self.target.value, 'No source guessing'

            return self.record

        monkeypatch.setattr(workflow, 'OwnedResponseEvidenceStore', FakeContentStore)
        monkeypatch.setattr(workflow, 'ReplayOwnedContentResponse', Product)
        monkeypatch.setattr(workflow, 'ParseResponseRecord', Parse)

    def Apply(self, **overrides):
        """Explicitly select content v1 in addition to ordinary independent PASSIVE admission."""

        return super().Apply(source_profile=_CONTENT_FAMILY.profile, **overrides)


@pytest.mark.parametrize('present', [False, True])
def test_ContentHeaderV2RecordsExactFamilyAndReplaysStrictVersion(monkeypatch, present):
    """Only v2 adds source_profile; predicate and check identity keep their original meaning."""

    environment = FakeContentEnvironment(monkeypatch, present=present)
    result = environment.Apply()
    assert result.state == 'completed', result.ToDict()
    assert result.condition_observed is not present, 'Interpret actual field-name presence'
    assert result.ToDict()['profile'] == 'owned-response-header-absence.v2', 'Explicit v2 summary'
    assert result.ToDict()['source_profile'] == _CONTENT_FAMILY.profile, 'Selected source identity'
    assert environment.selected_family is _CONTENT_FAMILY, 'No eager old-family store'
    assessment = next(item for item in environment.model.observations if
                      item.Reference() == result.assessment_reference)
    assert assessment.attributes['schema_version'] == 2, 'Strict new assessment version'
    assert set(assessment.attributes) == workflow._ASSESSMENT_FIELDS | {'source_profile'}, (
        'V2 must add exactly one closed field')
    assert set(assessment.attributes['authority_basis']) == workflow._BASIS_FIELDS | {
        'source_profile'}, 'Bind family in the original immutable authority basis'
    assert assessment.provenance.execution is None, 'Offline interpretation cannot invent execution'
    environment.Advance(1000)
    replay = environment.Replay(result)
    assert replay.condition_observed is not present, (
        'Historical proof recomputes the fixed predicate')
    assert replay.ToDict()['profile'] == 'owned-response-header-absence.v2', 'No v1 fallback'


@pytest.mark.parametrize('source_profile', ['', 'unknown', 'owned-response-capture.v2', None, True])
def test_HeaderUnknownSourceProfileRefusesBeforeAuthorityOrOriginalRead(
    monkeypatch, source_profile,
):
    """A misspelled or untyped source profile cannot invoke either original replay owner."""

    environment = FakeOriginalEnvironment(monkeypatch)

    with pytest.raises(NativeResponseHeaderError):
        environment.Apply(source_profile=source_profile)

    assert environment.source_reads == environment.model_saves == (
        environment.workspace_saves) == 0, (
        'No source, model or workspace work on malformed selection')


@pytest.mark.parametrize('edit', ['schema', 'profile', 'source', 'missing-source', 'basis-source',
                                 'extra', 'downgrade'])
def test_HeaderV2HistoricalRouteCannotDowngradeOrCrossFamilies(monkeypatch, edit):
    """Version/profile/basis mismatches remain invalid even with equal retained source hashes."""

    environment = FakeContentEnvironment(monkeypatch)
    result = environment.Apply()
    original = next(item for item in environment.model.observations if
                    item.Reference() == result.assessment_reference)
    attributes = json.loads(CanonicalModelJson(original.attributes))

    if edit == 'schema':
        attributes['schema_version'] = 1

    elif edit == 'profile':
        attributes['profile'] = 'owned-response-header-absence.v1'

    elif edit == 'source':
        attributes['source_profile'] = _CATALOG_FAMILY.profile

    elif edit == 'missing-source':
        del attributes['source_profile']

    elif edit == 'basis-source':
        attributes['authority_basis']['source_profile'] = _CATALOG_FAMILY.profile

    elif edit == 'extra':
        attributes['unexpected'] = True

    else:
        attributes.update(schema_version=1, profile='owned-response-header-absence.v1')
        del attributes['source_profile']

    changed = replace(original, attributes=attributes)
    environment.model = replace(environment.model, observations=tuple(
        changed if item == original else item for item in environment.model.observations))

    with pytest.raises(NativeResponseHeaderError):
        workflow.ReplayOwnedResponseHeaderCheck(environment.root, changed.Reference())


@pytest.mark.parametrize('failure', ['approval', 'permission', 'owner', 'scope', 'late'])
def test_ContentHeaderAdmissionStillPrecedesInterpretationAndPersistence(monkeypatch, failure):
    """Content retention supplies neither PASSIVE permission nor renewed scope/owner/TTL."""

    environment = FakeContentEnvironment(monkeypatch)
    options = {}

    if failure == 'approval':
        options['approve_passive_header_check'] = False

    elif failure == 'permission':
        environment.policy = replace(environment.policy, permissions=())

    elif failure == 'owner':
        options['current_owner_provider'] = lambda: 'operator:changed'

    elif failure == 'scope':
        environment.scope = replace(environment.scope, allow=(environment.target,))

    else:
        environment.on_product = environment.Advance

    result = environment.Apply(**options)
    assert result.state == 'denied', result.ToDict()
    assert environment.model_saves == environment.workspace_saves == 0, 'No Save after refusal'
    assert result.condition_observed is None and result.assessment_reference is None, (
        'No clean or positive result can be fabricated on refusal')


def test_ContentExactReuseRetainsOriginalAssessmentWithoutSecondSave(monkeypatch):
    """The v2 source-profile binding is immutable across reuse inside a fresh valid admission."""

    environment = FakeContentEnvironment(monkeypatch)
    first = environment.Apply()
    repeated = environment.Apply()
    assert repeated.state == 'already-applied', repeated.ToDict()
    assert repeated.assessment_reference == first.assessment_reference, 'No reattribution'
    assert (environment.model_saves, environment.workspace_saves) == (1, 1), 'No second CAS attempt'


@pytest.mark.parametrize('owner', ['model', 'workspace'])
def test_ContentPartialAckRemainsSeparateFromObservedCommittedState(monkeypatch, owner):
    """A lost return may expose committed state but never upgrade it to an actual ACK."""

    environment = FakeContentEnvironment(monkeypatch)
    setattr(environment, owner + '_ack', 'lost')
    result = environment.Apply()
    assert result.state == 'partial', result.ToDict()
    assert getattr(result, owner + '_commit') == 'observed-committed', 'No manufactured ACK'
    assert environment.model_saves == 1 and environment.workspace_saves == (
        int(owner == 'workspace')), (
        'One original-basis attempt per owner, without retry or repair')


def test_ContentFindingFingerprintMatchesExistingCatalogMeaning(monkeypatch):
    """Changing source families must not create another check identity for the same URL field."""

    environment = FakeContentEnvironment(monkeypatch)
    provenance = ModelProvenance('native.response-passive', 'analysis:unit',
        environment.now.isoformat(), 'scope:unit-scope', environment.target.Reference(), '1')
    source = workflow.OwnedHeaderSource(environment.target, environment.fact, environment.records,
        environment.headers, environment.receipt_id, 'job:unit-only', _CONTENT_FAMILY)
    old = replace(source, _family=_CATALOG_FAMILY)
    assert workflow.HeaderFinding(source, provenance).Fingerprint() == workflow.HeaderFinding(
        old, provenance).Fingerprint(), 'Source versions do not redefine field-name absence'
