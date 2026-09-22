"""Black-box known-answer contracts for the first-party web micro-target."""

from __future__ import annotations

import json

import pytest

from .conftest import ComposeLab
from .scenarios import WEB_MICRO_TARGET_CONTRACT

pytestmark = pytest.mark.serial


def test_WebMicroScenarioDeclaresKnownAnswerContract():
    """Keep every target route and bounded simulation explicit for later metrics."""

    scenario = WEB_MICRO_TARGET_CONTRACT

    assert scenario.target.provenance == "first-party:labs/targets/web-micro", (
        "web micro scenario declares known answer contract invariant failed."
    )
    assert scenario.required_capabilities == ("docker.compose", "http.get", "http.post"), (
        "web micro scenario declares known answer contract invariant failed."
    )
    assert scenario.expected_observations, (
        "web micro scenario declares known answer contract invariant failed."
    )
    assert scenario.expected_findings == (
        "simulated.command-execution",
        "simulated.file-inclusion",
        "simulated.ssrf",
        "simulated.upload-validation",
    ), "web micro scenario declares known answer contract invariant failed."


def test_WebMicroTargetExposesDeterministicSafeObservations(micro_target_lab: ComposeLab):
    """Exercise discovery, inputs, statuses, and simulation markers through HTTP only."""

    script = """
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, Request, build_opener
import json

opener = build_opener()

class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None

def request(path, method='GET', data=None, headers=None):
    request = Request(
        f'http://127.0.0.1:8080{path}',
        data=data,
        headers=headers or {},
        method=method,
    )
    try:
        response = opener.open(request, timeout=1)
        return response.status, dict(response.headers.items()), response.read().decode('utf-8')

    except HTTPError as error:
        return error.code, dict(error.headers.items()), error.read().decode('utf-8')

result = {}
status, headers, body = request('/')
result['root'] = {'status': status, 'body': json.loads(body)}
status, headers, body = request('/catalog')
result['catalog'] = {'status': status, 'body': json.loads(body)}
try:
    response = build_opener(NoRedirect()).open('http://127.0.0.1:8080/redirect', timeout=1)
    result['redirect'] = {'status': response.status, 'location': response.headers['Location']}

except HTTPError as error:
    result['redirect'] = {'status': error.code, 'location': error.headers['Location']}
status, headers, body = request('/headers')
result['headers'] = {'status': status, 'lab': headers['X-1337-Lab']}
status, headers, body = request('/cookie')
result['cookie'] = {'status': status, 'cookie': headers['Set-Cookie']}
status, headers, body = request('/form')
result['form'] = {'status': status, 'body': body}
status, headers, body = request('/query?item=demo')
result['query'] = {'status': status, 'body': json.loads(body)}
status, headers, body = request(
    '/json',
    method='POST',
    data=b'{"name":"demo"}',
    headers={'Content-Type': 'application/json'},
)
result['json'] = {'status': status, 'body': json.loads(body)}
status, headers, body = request('/submit', method='POST', data=b'query=fixture')
result['submit'] = {'status': status, 'body': json.loads(body)}
status, headers, body = request('/upload', method='POST', data=b'fixture')
result['upload'] = {'status': status, 'body': json.loads(body)}
for name in ('command-execution', 'file-inclusion', 'ssrf', 'upload'):
    status, headers, body = request(f'/canary/{name}')
    result[f'canary.{name}'] = {'status': status, 'body': json.loads(body)}
result['statuses'] = {}
for status_code in (400, 401, 403, 404, 500):
    status, headers, body = request(f'/status/{status_code}')
    result['statuses'][str(status_code)] = {'status': status, 'body': json.loads(body)}

print(json.dumps(result, sort_keys=True))
"""
    result = micro_target_lab.Execute(
        WEB_MICRO_TARGET_CONTRACT.target.compose_service,
        "python",
        "-c",
        script,
        timeout_seconds=WEB_MICRO_TARGET_CONTRACT.timeout_seconds,
    )

    assert result.returncode == 0, result.stderr
    observations = json.loads(result.stdout)
    assert observations["root"] == {
        "body": {"links": ["/catalog", "/form", "/headers", "/cookie"], "target": "web-micro"},
        "status": 200,
    }, "web micro target exposes deterministic safe observations invariant failed."
    assert observations["catalog"] == {
        "body": {"items": ["alpha", "beta"], "target": "web-micro"},
        "status": 200,
    }, "web micro target exposes deterministic safe observations invariant failed."
    assert observations["headers"] == {"lab": "web-micro", "status": 200}, (
        "web micro target exposes deterministic safe observations invariant failed."
    )
    assert observations["redirect"] == {"location": "/catalog", "status": 302}, (
        "web micro target exposes deterministic safe observations invariant failed."
    )
    assert observations["cookie"] == {
        "cookie": "lab_session=deterministic; HttpOnly; SameSite=Strict",
        "status": 200,
    }, "web micro target exposes deterministic safe observations invariant failed."
    assert 'action="/submit"' in observations["form"]["body"], (
        "web micro target exposes deterministic safe observations invariant failed."
    )
    assert observations["query"] == {"body": {"item": "demo"}, "status": 200}, (
        "web micro target exposes deterministic safe observations invariant failed."
    )
    assert observations["json"] == {"body": {"accepted": True, "keys": ["name"]}, "status": 200}, (
        "web micro target exposes deterministic safe observations invariant failed."
    )
    assert observations["submit"] == {
        "body": {"accepted": True, "simulation": "form"},
        "status": 200,
    }, "web micro target exposes deterministic safe observations invariant failed."
    assert observations["upload"] == {
        "body": {"accepted": False, "simulation": "upload-validation"},
        "status": 200,
    }, "web micro target exposes deterministic safe observations invariant failed."
    assert observations["canary.command-execution"] == {
        "body": {"simulation": "command-execution"},
        "status": 200,
    }, "web micro target exposes deterministic safe observations invariant failed."
    assert observations["canary.file-inclusion"] == {
        "body": {"simulation": "file-inclusion"},
        "status": 200,
    }, "web micro target exposes deterministic safe observations invariant failed."
    assert observations["canary.ssrf"] == {
        "body": {"outbound_requests": 0, "simulation": "ssrf"},
        "status": 200,
    }, "web micro target exposes deterministic safe observations invariant failed."
    assert observations["canary.upload"] == {
        "body": {"simulation": "upload-validation"},
        "status": 200,
    }, "web micro target exposes deterministic safe observations invariant failed."
    assert observations["statuses"] == {
        str(status_code): {"body": {"status": status_code}, "status": status_code}
        for status_code in (400, 401, 403, 404, 500)
    }, "web micro target exposes deterministic safe observations invariant failed."
