# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Labelled executor doubles verify content custody and shared owners without acquisition."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from fuzzy1337 import owned_response_capture as parent
from fuzzy1337 import owned_response_custody as custody
from fuzzy1337 import owned_response_workflow as product
from fuzzy1337.adapters import ImpactLevel
from fuzzy1337.adapters.owned_content_response import BytePart, RequestBytes
from fuzzy1337.evidence import EvidenceRecord, EvidenceReference
from fuzzy1337.model import LocalModelStore
from fuzzy1337.policy import CapabilityPermission, GovernedLocalExecutor, ImpactPolicy
from fuzzy1337.scope import LocalScopeStore, Target, TargetKind
from fuzzy1337.workspace import LocalWorkspaceStore, WorkspaceConfiguration
from tests.unit.test_owned_response_parent import AT, URL, Authority, Result
from tests.unit.test_owned_response_parent import private_system as private_system
from tests.unit.test_owned_response_parent import runner as runner

CONTENT_URL = 'http://127.0.0.1:32123/content/original'


def OriginalRecord(url=CONTENT_URL, *, error=None, body=b'original arbitrary text'):
    """Encode hand-selected response bytes, not a producer fixture or expected detector result."""

    if error is not None:
        return custody.Canonical({'schema_version': 1,
            'profile': 'owned-content-response-capture.v1', 'outcome': 'refused', 'error': error})

    headers = (b'HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n'
        b'Connection: close\r\nContent-Length: ' + str(len(body)).encode() + b'\r\n\r\n')

    return custody.Canonical({'schema_version': 1, 'profile': 'owned-content-response-capture.v1',
        'outcome': 'captured', 'url': url, 'address': '127.0.0.1', 'port': 32123,
        'media_type': 'text/plain', 'request': BytePart(RequestBytes(url)),
        'response_headers': BytePart(headers), 'response_body': BytePart(body),
        'response': {'size_bytes': len(headers + body),
            'sha256': hashlib.sha256(headers + body).hexdigest()}})


@pytest.fixture
def content(tmp_path, monkeypatch, private_system):
    """Keep canonical owners real and substitute only the governed process result boundary."""

    root = tmp_path / 'workspace'
    LocalWorkspaceStore(root).Create(WorkspaceConfiguration('Content unit'), 'workspace')
    LocalModelStore(root).Create()
    authority = Authority(URL)
    target = Target(TargetKind.URL, CONTENT_URL)
    ip = Target(TargetKind.IP, '127.0.0.1')
    scope = replace(authority.context.scope, targets=(target, ip), allow=(target, ip))
    LocalScopeStore(root).Create(scope)
    policy = ImpactPolicy('content', permissions=(CapabilityPermission(
        'http.owned-content-response-capture', 'native.loopback-content-response',
        ImpactLevel.SAFE),))
    state = SimpleNamespace(root=root, policy=policy, raw=OriginalRecord(), error=None, calls=[])

    async def Execute(self, request, *, context_provider, on_event, **kwargs):
        """Return explicit original fragments only after the original fresh authority guard."""

        context_provider()
        state.calls.append(request)
        result = Result(state.raw, error=state.error)

        for event in result.events:
            on_event(event)

        return result

    monkeypatch.setattr(GovernedLocalExecutor, 'Execute', Execute)

    return state


def Capture(content, runner, **kwargs):
    """Compose the actual owner with a deterministic executor double and explicit two opt-ins."""

    options = {'approve_safe_content_response_capture': True, 'retain_response': True,
               'clock': lambda: AT}
    options.update(kwargs)

    return runner.run(product.RunOwnedContentResponseCapture(content.root, 'lab', CONTENT_URL,
        'operator:execution', lambda: content.policy, **options))


def test_ContentPlanDescribesRetentionWithoutGrantOrWork(content):
    """New capability and retention intent cannot silently invoke the catalog family."""

    plan = product.PlanOwnedContentResponseCapture(content.root, 'lab', CONTENT_URL,
        'operator:execution', lambda: content.policy, clock=lambda: AT).ToDict()
    assert (
        plan['retention_required'] is True and plan['execution_authorized'] is False
    ), (
        'Planning describes retention without authorizing execution'
    )
    assert (
        plan['source_id'] == 'native.loopback-content-response'
    ), (
        'Planning must select the distinct content provider'
    )
    assert (
        plan['invocation']['request']['parameters'] == {
        'url': CONTENT_URL, 'retain_response': True}
    ), (
        'The fixed recipe must bind the explicit retention selection'
    )
    assert (
        not content.calls and not tuple(content.root.glob('owned-response-*'))
    ), (
        'Refusal and planning must precede execution and private work'
    )


@pytest.mark.parametrize('option,value,exception', [
    ('approve_safe_content_response_capture', False, PermissionError),
    ('retain_response', False, PermissionError), ('retain_response', 1, ValueError),
    ('approve_safe_content_response_capture', 1, ValueError),
])
def test_ContentSeparateExactOptInsPrecedeGrantOrWork(content, runner, option, value, exception):
    """An existing SAFE permission cannot substitute for either independent exact consent."""

    with pytest.raises(exception):
        Capture(content, runner, **{option: value})

    assert (
        not content.calls and not tuple(content.root.glob('owned-response-*'))
    ), (
        'Refusal and planning must precede execution and private work'
    )


def test_ContentOriginalWireAndSevenIdsSurviveOfflineReplay(content, runner, monkeypatch):
    """Uncatalogued bytes and normalized media remain source facts under their actual IDs."""

    outcome = Capture(content, runner)
    assert outcome.ExitCode() == 0, outcome.ToDict()
    assert (
        len(outcome.records) == 7 and outcome.custody_status == 'complete'
    ), (
        'Successful custody requires exactly seven original acknowledged roles'
    )
    assert (
        outcome.model_persistence_status == outcome.workspace_persistence_status == (
        'acknowledged')
    ), (
        'Whole success requires both original durable acknowledgements'
    )
    assert (
        outcome.ToDict()['workflow'] == 'owned-content-response-capture'
    ), (
        'The content workflow must keep its distinct identity'
    )
    facts = outcome.source_facts
    assert (
        set(facts) == {'schema_version', 'profile', 'original_job_id', 'original_receipt_id',
        'original_role_ids', 'request_sha256', 'response_sha256', 'header_size_bytes',
        'body_size_bytes', 'media_type'}
    ), (
        'Content source facts must not invent catalog or case metadata'
    )
    assert (
        facts['media_type'] == 'text/plain'
    ), (
        'Retain the admitted normalized response media'
    )
    request = content.calls[0]
    assert (
        request.resources.max_stdout_bytes == 131072
    ), (
        'Apply the new fixed stdout cap without narrowing accepted originals'
    )
    assert (
        request.invocation.argv[-2:] == ('fuzzy1337.owned_content_response_worker', CONTENT_URL)
    ), (
        'Only the selected fixed installed content worker may execute'
    )
    assert (
        request.invocation.request.parameters == {'url': CONTENT_URL, 'retain_response': True}
    ), (
        'The original invocation must bind URL and explicit retention'
    )
    store = custody.OwnedResponseEvidenceStore(content.root / 'evidence',
                                              _family=custody._CONTENT_FAMILY)
    body = next(item for item in outcome.records if item.reference.role == 'owned-response-body')
    assert (
        body.reference.media_type == 'application/octet-stream'
    ), (
        'Original content body bytes use the fixed octet-stream evidence media'
    )
    assert (
        store.Read(body.reference) == b'original arbitrary text'
    ), (
        'Store the selected original response bytes without catalog substitution'
    )

    def Refuse(*args, **kwargs):
        """Trip all acquisition, authority and write paths during historical verification."""

        pytest.fail('Historical replay may only read retained original owners')

    monkeypatch.setattr(GovernedLocalExecutor, 'Execute', Refuse)
    monkeypatch.setattr(LocalScopeStore, 'Open', Refuse)
    monkeypatch.setattr(LocalModelStore, 'Save', Refuse)
    monkeypatch.setattr(LocalWorkspaceStore, 'Save', Refuse)
    replay = product.ReplayOwnedContentResponse(content.root, outcome.original_receipt_id)
    assert (
        replay.source_facts == facts
    ), (
        'Replay must preserve the original immutable source fact'
    )
    assert (
        replay.ToDict()['original_role_ids'] == outcome.ToDict()['original_role_ids']
    ), (
        'Offline replay must preserve all seven original manifest IDs'
    )
    assert (
        replay.ToDict()['workflow'] == 'owned-content-response-replay'
    ), (
        'Historical content replay must retain its distinct workflow identity'
    )

    with pytest.raises(ValueError):
        product.ReplayOwnedResponse(content.root, outcome.original_receipt_id)


@pytest.mark.parametrize('error', ['input', 'connection', 'timeout', 'protocol',
                                 'response-policy', 'body-policy'])
def test_ContentRoutineRefusalRetainsOnlyThreeOriginalControlRoles(content, runner, error):
    """Admitted worker refusal is neither captured source nor seven-part successful custody."""

    content.raw = OriginalRecord(error=error)
    content.error = error
    outcome = Capture(content, runner)
    assert (
        outcome.acquisition_outcome == 'refused' and outcome.custody_status == 'complete'
    ), (
        'Routine refusal may have complete control custody without a captured source'
    )
    assert (
        {item.reference.role for item in outcome.records} == {
        'stdout', 'stderr', 'owned-response-receipt'}
    ), (
        'Admitted refusal has exactly three original control roles'
    )
    assert (
        outcome.source_facts is None and not LocalModelStore(content.root).Open().observations
    ), (
        'A refused response cannot create a captured source observation'
    )


@pytest.mark.parametrize('change', ['family', 'retention', 'worker', 'stdout'])
def test_ContentFixedFullRequestRejectsCrossFamilyOrChangedRetention(content, change):
    """New full-request grammar cannot accept a legacy recipe or dropped retention parameter."""

    invocation = parent.PrepareResponseInvocation(CONTENT_URL,
                                                        _family=custody._CONTENT_FAMILY)
    from fuzzy1337.executors import CapabilityDescriptor, ExecutionResources, LocalExecutionRequest
    from fuzzy1337.owned_response_workflow import CurrentAuthority
    from fuzzy1337.policy import PolicyEngine

    authority = CurrentAuthority(content.root, 'lab', CONTENT_URL, 'operator:execution',
        lambda: content.policy, True, _family=custody._CONTENT_FAMILY, retain_response=True)
    capability = CapabilityDescriptor('http.owned-content-response-capture',
        'native.loopback-content-response', ImpactLevel.SAFE)
    grant = PolicyEngine().Authorize(invocation, capability, authority.context, at=AT)
    work = 'owned-response-' + 'a' * 32 + '/work'
    env = {key: '' for key in ('PATH', 'COMSPEC', 'PATHEXT', 'SYSTEMROOT', 'WINDIR')}
    env.update(LANG='C', LC_ALL='C', TEMP='/unit/' + work, TMP='/unit/' + work)
    value = json.loads(custody.Canonical(LocalExecutionRequest(invocation, capability,
        grant.authorization, work, env, ExecutionResources(131072, 1, 0.5))))
    custody.ValidateRequest(value, CONTENT_URL, _family=custody._CONTENT_FAMILY)

    if change == 'family':
        value['invocation']['adapter_id'] = 'native.loopback-response'

    elif change == 'retention':
        del value['invocation']['request']['parameters']['retain_response']

    elif change == 'worker':
        value['invocation']['argv'][-2] = 'fuzzy1337.owned_response_capture_worker'

    else:
        value['resources']['max_stdout_bytes'] = 8192

    with pytest.raises(ValueError):
        custody.ValidateRequest(value, CONTENT_URL, _family=custody._CONTENT_FAMILY)


def test_ContentReceiptRolePreflightRefusesForeignHugeBlobBeforeRead(content, monkeypatch):
    """A malicious receipt ID cannot turn inherited eager Get into a foreign-role blob read."""

    from fuzzy1337.evidence import EvidenceProvenance

    store = custody.OwnedResponseEvidenceStore(content.root / 'evidence',
                                              _family=custody._CONTENT_FAMILY)
    reference = EvidenceReference('foreign', 'blobs/sha256/' + '0' * 64, '0' * 64,
                                   'application/octet-stream', 10**12)
    record = EvidenceRecord(reference, EvidenceProvenance('workspace', 'scope:lab',
        'native.loopback-content-response', '1', '1', AT.isoformat(), AT.isoformat()))
    monkeypatch.setattr(store, 'ReadStoredBytes', lambda parts, maximum: custody.Canonical(
        record.ToDict()))
    monkeypatch.setattr(store, 'Read', lambda reference: pytest.fail('Foreign blob read'))

    with pytest.raises(ValueError, match='receipt family'):
        custody.ReplayOwnedResponseCapture(store, record.evidence_id)


def test_ContentClosedBindingCannotBeForgedByEqualDataclass():
    """Internal family data is not a caller-injected adapter or process recipe."""

    with pytest.raises(ValueError, match='family'):
        custody.ResponseDestination(CONTENT_URL, replace(custody._CONTENT_FAMILY))
