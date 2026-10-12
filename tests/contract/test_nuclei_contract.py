# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Optional Nuclei declarations and profile provenance bind existing SDK consumers."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

from fuzzy1337.adapters import AdapterRequest, ImpactLevel, SerializeContract
from fuzzy1337.adapters.nuclei import NucleiAdapter, NucleiProfile, NucleiTemplate
from fuzzy1337.executors import CapabilityDescriptors, InvocationDigest


def test_ProfileDigestBindsEveryReviewAndArtifactField(tmp_path):
    """Different review or source provenance cannot reuse an invocation authorization digest."""

    template_path = tmp_path / "owned.yaml"
    raw = (Path(__file__).parents[1] / "fixtures/nuclei/reviewed-get.yaml").read_bytes()
    template_path.write_bytes(raw)
    configuration_path = tmp_path / "empty.yaml"
    configuration_path.write_bytes(b"{}\n")
    template = NucleiTemplate("owned-http-marker", str(template_path),
        hashlib.sha256(raw).hexdigest(), len(raw), "fixture:owned", "1",
        "review:exact-source-controlled-fixture", "single-get-exact-url")
    profile = NucleiProfile("owned-http", (template,), str(configuration_path))
    request = AdapterRequest("web.http-template-check", "target:fixture", ImpactLevel.STANDARD,
        {"url": "http://127.0.0.1:8080/", "profile_sha256": profile.Digest,
         "timeout_seconds": 10, "rate_limit": 1})
    adapter = NucleiAdapter(lambda reference: b"", profile, provider_version="3.4.10")
    invocation = adapter.PrepareInvocation(request)
    changed = replace(profile, templates=(replace(template, review_reference="review:new"),))
    changed_request = replace(request, parameters={**request.parameters,
                                                   "profile_sha256": changed.Digest})
    changed_invocation = NucleiAdapter(lambda reference: b"", changed,
        provider_version="3.4.10").PrepareInvocation(changed_request)

    assert profile.Digest != changed.Digest, "Review changes must invalidate selected provenance."
    assert InvocationDigest(invocation) != InvocationDigest(changed_invocation), (
        "Authorization must bind the reviewed set even when argv paths are identical."
    )
    assert json.loads(SerializeContract(invocation))["provider_version"] == "3.4.10", (
        "Existing serialization must retain exact observed provider version."
    )
    assert CapabilityDescriptors(adapter.Descriptor)[0].maximum_impact is ImpactLevel.STANDARD, (
        "The existing executor declaration remains upstream of adapter execution."
    )


def test_BaseSdkImportDoesNotLoadNuclei():
    """SDK import preserves optional-provider startup and does not install or import scanners."""

    code = 'import sys; import fuzzy1337.adapters; '
    code += 'assert "fuzzy1337.adapters.nuclei" not in sys.modules'
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                            timeout=10, check=False)

    assert result.returncode == 0, "The base SDK must remain independent of optional Nuclei."
