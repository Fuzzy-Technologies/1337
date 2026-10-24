# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Pure crawl input, original-metadata and adapter checks without worker or target execution."""

import hashlib
from copy import deepcopy
from dataclasses import replace

import pytest

from fuzzy1337.adapters import (
    AdapterExecution,
    AdapterReport,
    AdapterRequest,
    EvidenceReference,
    ExecutionState,
    ImpactLevel,
    SerializeContract,
    ToolAdapter,
)
from fuzzy1337.adapters.native_crawl import (
    ERROR_CODES,
    EXCLUSION_CODES,
    MAX_INPUT_BYTES,
    MAX_RECORD_BYTES,
    NATIVE_CRAWL_CAPABILITY,
    NATIVE_CRAWL_PROFILE,
    BuildCrawlInput,
    CanonicalRecord,
    CrawlEndpoint,
    CrawlRequestBytes,
    CrawlTemplate,
    EncodeCrawlInput,
    NativeCrawlAdapter,
    NativeCrawlRecordError,
    ParseCrawlInput,
    ParseCrawlRecord,
)

URL = "http://127.0.0.1:8080/index"
LEAF = "http://127.0.0.1:8080/leaf"


def Input():
    """Supply explicit non-secret metadata, never a scope or live execution grant."""

    return BuildCrawlInput("unit", URL, URL, (URL, LEAF))


def Record():
    """Describe a synthetic complete empty response without claiming actual worker execution."""

    document = Input()
    template = CrawlTemplate("unit", URL)
    request = CrawlRequestBytes(URL)
    header = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Type: text/html\r\n\r\n"

    return {"schema_version": 1, "profile": NATIVE_CRAWL_PROFILE, "outcome": "html",
        "input_sha256": hashlib.sha256(EncodeCrawlInput(document)).hexdigest(),
        "selected_urls_sha256": hashlib.sha256(
            SerializeContract(document["selected_urls"]).encode()).hexdigest(),
        "source": {"url": URL, "address": "127.0.0.1", "port": 8080,
            "request_reference": template.Reference(),
            "endpoint_reference": template.endpoint.Identity().Reference(),
            "request_size_bytes": len(request),
            "request_sha256": hashlib.sha256(request).hexdigest()},
        "response": {"http_version": "HTTP/1.1", "status": 200, "media_type": "text/html",
            "header_bytes": len(header), "header_fields": 2, "body_bytes": 0,
            "body_sha256": hashlib.sha256(b"").hexdigest()},
        "frontier": {"complete": True, "anchor_count": 0, "entries": [],
            "exclusion_counts": dict.fromkeys(EXCLUSION_CODES, 0)}}


def LinkedRecord():
    """Supply a handwritten metadata envelope for identity/ordinal parsing, not detector truth."""

    record = Record()
    body = b'<a href="/leaf">unit</a><a href="/leaf">again</a>'
    template = CrawlTemplate("unit", LEAF)
    record["response"].update(body_bytes=len(body), body_sha256=hashlib.sha256(body).hexdigest())
    record["frontier"].update(anchor_count=2, entries=[{"url": LEAF,
        "request_reference": template.Reference(),
        "endpoint_reference": template.endpoint.Identity().Reference(), "ordinals": [1, 2]}])

    return record


def Report(raw=None, stderr=b""):
    """Bind synthetic stream bytes to SDK metadata without inventing genuine launch evidence."""

    streams = {"stdout": CanonicalRecord(Record()) if raw is None else raw, "stderr": stderr}
    adapter = NativeCrawlAdapter(lambda reference: streams[reference.role])
    invocation = adapter.PrepareInvocation(AdapterRequest(NATIVE_CRAWL_CAPABILITY,
        CrawlEndpoint(URL)[0].Reference(), ImpactLevel.SAFE, Input()))
    references = tuple(EvidenceReference(role, "blobs/" + role, hashlib.sha256(value).hexdigest(),
        "application/octet-stream", len(value)) for role, value in streams.items())

    return adapter, AdapterReport(invocation, AdapterExecution(ExecutionState.SUCCEEDED, 0, 0.1),
                                  references)


def test_PureInputUsesExistingImmutableInvocationAndRequestOwners():
    """Preparation carries exactly one admitted JSON argument and grants no authority."""

    document = Input()
    raw = EncodeCrawlInput(document)
    assert ParseCrawlInput(raw) == document and len(raw) <= MAX_INPUT_BYTES, (
        "The fixed input lost its canonical round-trip or byte ceiling."
    )
    adapter, report = Report()
    assert isinstance(adapter, ToolAdapter), "The adapter lost the existing ToolAdapter boundary."
    assert report.invocation.argv[1:4] == ("-I", "-m", "fuzzy1337.native_crawl_worker"), (
        "The worker must remain one fixed isolated packaged module."
    )
    assert report.invocation.argv[4].encode() == raw and report.invocation.timeout_seconds == 4, (
        "The exact argument or startup-inclusive request deadline changed."
    )
    assert report.invocation.request.parameters["selected_urls"] == (URL, LEAF), (
        "The existing immutable request owner must freeze the complete selected set."
    )
    assert adapter.Descriptor.maximum_impact is ImpactLevel.SAFE, "Impact classification widened."
    assert adapter.CheckHealth().provider_version == "1", "Provider contract version drifted."
    assert CrawlEndpoint("http://[::1]:8080/index")[1:] == ("::1", 8080, "/index", "[::1]:8080"), (
        "The exact literal IPv6 destination was rewritten."
    )
    assert b"Host: [::1]:8080\r\n" in CrawlRequestBytes("http://[::1]:8080/index"), (
        "IPv6 Host authority lost its required brackets."
    )
    assert CrawlEndpoint("http://127.0.0.1/")[2] == 80, "Canonical implicit port semantics changed."


@pytest.mark.parametrize("url", [
    "http://localhost/", "http://127.0.0.2/", "https://127.0.0.1/", "http://127.0.0.1:80/",
    "http://127.0.0.1", "http://127.0.0.1/?", "http://127.0.0.1/#", "http://u:p@127.0.0.1/",
    "http://127.0.0.1/%41", "http://127.0.0.1/{id}", "http://127.0.0.1/..",
    "http://[0:0:0:0:0:0:0:1]/", "http://127.0.0.1/" + "x" * 1025, None, True, "\ud800",
])
def test_OnlyExactSelectedLoopbackStructuralUrlsAreAdmitted(url):
    """Unsupported URLs are refused without normalization, DNS or any target contact."""

    with pytest.raises(NativeCrawlRecordError):
        CrawlEndpoint(url)


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 1.0), ("profile", "other"),
    ("workspace_id", "Bad"), ("workspace_id", "x" * 65), ("selected_urls", []),
    ("selected_urls", [LEAF, URL]), ("selected_urls", [URL, URL]),
    ("selected_urls", [LEAF]), ("selected_urls", [URL, "http://127.0.0.1:8081/leaf"]),
    ("max_body_bytes", True), ("max_body_bytes", 65537), ("request_timeout_ms", 49),
    ("request_timeout_ms", 5001), ("owner_reference", "not-worker-owned"),
])
def test_InputFieldsCannotWidenTheFixedProfile(field, value):
    """Input metadata excludes authority fields, coercion, missing membership and origin drift."""

    document = Input()
    document[field] = value

    with pytest.raises(NativeCrawlRecordError):
        EncodeCrawlInput(document)


@pytest.mark.parametrize("raw", [
    b"", b"x" * (MAX_INPUT_BYTES + 1), b"[]", b"{} ", b'{"x":1,"x":2}',
    b'{"x":NaN}', b'{"x":Infinity}', b'{"x":1.0}', b'{"x":"\\ud800"}',
    b'{"x":"\\u00e9"}', b"\xff", b"\xef\xbb\xbf{}", b"[[[[[[[[[0]]]]]]]]]",
])
def test_InputRequiresBoundedUniqueCanonicalExactPrimitiveJson(raw):
    """Ambiguous JSON and Unicode cannot be repaired into an admitted worker argument."""

    with pytest.raises(NativeCrawlRecordError):
        ParseCrawlInput(raw)


@pytest.mark.parametrize("document", [
    {"nested": [[[[[[[[0]]]]]]]]}, {str(index): 0 for index in range(4097)},
    {"items": [0] * 4097}, {"items": [0] * 4095, "extra": 0}, {"text": "x" * 65536},
])
def test_CanonicalCodecEnforcesNodeDepthAndEncodedByteBounds(document):
    """Untrusted metadata cannot render beyond finite budgets before field admission."""

    with pytest.raises(NativeCrawlRecordError):
        CanonicalRecord(document)


def test_ImmutableSelectionAndEmptyBodyNecessaryFactsRemainExplicit():
    """A mutable selection is not accepted by the builder and empty bytes cannot contain anchors."""

    with pytest.raises(NativeCrawlRecordError):
        BuildCrawlInput("unit", URL, URL, [URL, LEAF])

    record = Record()
    record["frontier"]["anchor_count"] = 1
    record["frontier"]["exclusion_counts"]["not-admitted"] = 1

    with pytest.raises(NativeCrawlRecordError):
        ParseCrawlRecord(CanonicalRecord(record), Input())


@pytest.mark.parametrize("section,field,value", [
    (None, "schema_version", True), (None, "input_sha256", "0" * 64),
    (None, "selected_urls_sha256", "0" * 64), (None, "outcome", "clean"),
    (None, "profile", "other"), ("source", "port", True), ("source", "address", "::1"),
    ("source", "request_sha256", "0" * 64), ("source", "url", LEAF),
    ("response", "body_bytes", True), ("response", "body_bytes", 16385),
    ("response", "body_sha256", "0" * 64), ("response", "body_sha256", "A" * 64),
    ("response", "http_version", "HTTP/2"), ("response", "status", 302),
    ("response", "media_type", "text/plain"), ("response", "header_bytes", 1),
    ("response", "header_fields", 65), ("frontier", "complete", 1),
    ("frontier", "anchor_count", 1), ("frontier", "entries", {}),
    ("response", "raw_body", "never retained"),
])
def test_OriginalRecordJoinsAndNecessaryFactsFailClosed(section, field, value):
    """Schema-valid primitive shapes alone cannot establish worker input/peer/response joins."""

    record = Record()
    selected = record if section is None else record[section]
    selected[field] = value

    with pytest.raises(NativeCrawlRecordError):
        ParseCrawlRecord(CanonicalRecord(record), Input())


def test_CandidateReferencesAndOccurrencesAreIndependentlyRecomputed():
    """Duplicate/foreign candidates and reused ordinals never become a complete frontier."""

    record = LinkedRecord()
    assert ParseCrawlRecord(CanonicalRecord(record), Input()) == record, (
        "The handwritten identity/ordinal envelope failed pure admission."
    )

    for field, value in (("url", "http://127.0.0.1:8080/private"),
                         ("url", URL), ("request_reference", "request:" + "0" * 64),
                         ("endpoint_reference", "object:" + "0" * 64),
                         ("ordinals", [2, 1]), ("ordinals", [1, 1]),
                         ("ordinals", [0]), ("ordinals", []), ("ordinals", [3])):
        changed = deepcopy(record)
        changed["frontier"]["entries"][0][field] = value

        with pytest.raises(NativeCrawlRecordError):
            ParseCrawlRecord(CanonicalRecord(changed), Input())

    changed = deepcopy(record)
    changed["frontier"]["entries"] *= 2

    with pytest.raises(NativeCrawlRecordError):
        ParseCrawlRecord(CanonicalRecord(changed), Input())


@pytest.mark.parametrize("outcome,status,media", [("non-html", 200, "text/plain"),
    ("non-html", 200, "application/octet-stream"), ("client-error", 404, "text/html")])
def test_AdmittedTerminalResponsesHaveOnlyTheExactEmptyFrontier(outcome, status, media):
    """A terminal response is an observation, not a scanner true negative or lexical result."""

    record = Record()
    record.update(outcome=outcome)
    record["response"].update(status=status, media_type=media, header_bytes=100)
    assert ParseCrawlRecord(CanonicalRecord(record), Input()) == record, (
        "An admitted terminal response lost its exact empty frontier."
    )
    record["frontier"]["exclusion_counts"]["not-admitted"] = 1
    record["frontier"]["anchor_count"] = 1

    with pytest.raises(NativeCrawlRecordError):
        ParseCrawlRecord(CanonicalRecord(record), Input())


@pytest.mark.parametrize("code", sorted(ERROR_CODES))
def test_ClosedRefusalsNeverContainResponseMetadata(code):
    """Parent failure classification can parse refusals without treating them as success."""

    record = {"schema_version": 1, "profile": NATIVE_CRAWL_PROFILE,
              "outcome": "refused", "error": code}
    assert ParseCrawlRecord(CanonicalRecord(record), Input()) == record, (
        "A fixed safe refusal could not be classified by the parent parser."
    )
    record["body_sha256"] = "0" * 64

    with pytest.raises(NativeCrawlRecordError):
        ParseCrawlRecord(CanonicalRecord(record), Input())


def test_UndeclaredRefusalAndCorruptActualEvidenceCannotNormalize():
    """Fixed-code admission and original-byte hash verification precede every observation."""

    record = {"schema_version": 1, "profile": NATIVE_CRAWL_PROFILE,
              "outcome": "refused", "error": "private-unknown"}

    with pytest.raises(NativeCrawlRecordError):
        ParseCrawlRecord(CanonicalRecord(record), Input())

    _, report = Report()
    corrupt_reader = NativeCrawlAdapter(lambda _reference: b"corrupt-original")

    with pytest.raises(NativeCrawlRecordError):
        corrupt_reader.NormalizeReport(report)


def test_AdapterNormalizesOnlyVerifiedOriginalSuccessAndPreservesTargetBindings():
    """Synthetic original-report joins exercise the SDK without claiming a genuine launch."""

    adapter, report = Report(CanonicalRecord(LinkedRecord()))
    result = adapter.NormalizeReport(report)
    assert [item.kind for item in result.observations] == [
        "web.owned-crawl-response", "web.owned-crawl-link"], "Observation boundaries changed."
    assert result.observations[1].subject_reference == CrawlEndpoint(LEAF)[0].Reference(), (
        "Candidate observations must retain the exact Target binding for the parent."
    )
    assert not result.findings and not result.object_enrichments, (
        "The producer must not invent Findings or own model projection."
    )

    for changed in (replace(report, invocation=replace(report.invocation,
                        argv=(*report.invocation.argv, "extra"))),
                    replace(report, evidence=report.evidence[:1]),
                    replace(report, evidence=tuple(reversed(report.evidence))),
                    replace(report, execution=AdapterExecution(ExecutionState.FAILED, 2, 0.1))):
        with pytest.raises(NativeCrawlRecordError):
            adapter.NormalizeReport(changed)

    for output, stderr in ((b"x" * (MAX_RECORD_BYTES + 1), b""),
                           (CanonicalRecord(Record()), b"x"),
                           (CanonicalRecord({"schema_version": 1, "profile": NATIVE_CRAWL_PROFILE,
                                             "outcome": "refused", "error": "timeout"}), b"")):
        other, changed = Report(output, stderr)

        with pytest.raises(NativeCrawlRecordError):
            other.NormalizeReport(changed)


@pytest.mark.parametrize("change", ["capability", "impact", "credentials", "target"])
def test_PreparationCannotSubstituteCapabilityAuthorityOrSource(change):
    """Fixed preparation accepts no alternative capability, actor or invocation target."""

    adapter, report = Report()
    request = report.invocation.request
    changes = {"capability": {"capability": "other"},
               "impact": {"impact": ImpactLevel.STANDARD},
               "credentials": {"credential_references": ("credential:unit",)},
               "target": {"target_reference": "target:other"}}

    with pytest.raises(NativeCrawlRecordError):
        adapter.PrepareInvocation(replace(request, **changes[change]))
