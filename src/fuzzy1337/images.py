# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental verified offline image, package, SBOM and vulnerability ingestion."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast
from urllib.parse import unquote

from fuzzy1337.adapters import AdapterReport, ExecutionState
from fuzzy1337.adapters.trivy import ParseJson
from fuzzy1337.evidence import EvidenceRecord, LocalEvidenceStore, NormalizeEvidenceTime
from fuzzy1337.executors import InvocationDigest
from fuzzy1337.findings import (
    ApplyVerifiedFindings,
    Finding,
    FindingSeverity,
    Remediation,
)
from fuzzy1337.model import (
    CanonicalModelJson,
    ModelDelta,
    ModelProvenance,
    ModelState,
    ObjectIdentity,
    ObjectKind,
    Observation,
    Relation,
    RelationKind,
    SecurityObject,
)
from fuzzy1337.workspace import LocalWorkspaceStore

IMAGE_CONTRACT_VERSION = 1
IMAGE_IMPORT_MAX_BYTES = 4 * 1024 * 1024
IMAGE_IMPORT_MAX_ITEMS = 4096
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TYPE = re.compile(r"[a-z][a-z0-9.+-]*\Z")
_BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")

__all__ = [
    "IMAGE_CONTRACT_VERSION", "IMAGE_IMPORT_MAX_BYTES", "IMAGE_IMPORT_MAX_ITEMS",
    "ImageIdentity", "PackageIdentity", "ApplyVerifiedTrivyImages", "ApplyVerifiedCycloneDx",
]


def Text(value: object) -> str:
    """Require finite nonempty UTF-8 identity text without control characters.

    Args:
        value: Explicit identity/advisory text; arbitrary raw metadata is not accepted here.

    Returns:
        Validated nonempty text with a 2,048-character limit.
    """

    if not isinstance(value, str) or not value or len(value) > 2048 or any(
        ord(character) < 32 or ord(character) == 127 for character in value
    ):
        raise ValueError("image import requires bounded nonempty identity text")

    try:
        value.encode("utf-8")

    except UnicodeError as error:
        raise ValueError("image import text must be valid UTF-8") from error

    return value


def Digest(value: object) -> str:
    """Require an explicit lowercase SHA-256 digest with its algorithm prefix.

    Args:
        value: Provider-observed image/layer digest; tags cannot identify content.

    Returns:
        Validated sha256-prefixed digest without hashing or reading an artifact.
    """

    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError("image identity requires an explicit lowercase SHA-256 digest")

    return value


def Items(value: object) -> list[object]:
    """Validate finite provider arrays without treating malformed data as empty.

    Args:
        value: Decoded JSON array within the independent item-count budget.

    Returns:
        Original bounded array; null handling belongs to the explicit caller profile.
    """

    if not isinstance(value, list) or len(value) > IMAGE_IMPORT_MAX_ITEMS:
        raise ValueError("image import collections require a bounded array")

    return value


def Record(value: object) -> dict[str, object]:
    """Require a provider JSON object before accessing interpretation fields.

    Args:
        value: Decoded JSON object, not a collection or absent field.

    Returns:
        Typed mapping without trusting or copying arbitrary provider fields.
    """

    if not isinstance(value, dict):
        raise ValueError("image import requires JSON objects")

    return cast(dict[str, object], value)


@dataclass(frozen=True, slots=True)
class ImageIdentity:
    """Keep image config and manifest digests distinct for later runtime correlation."""

    digest: str
    digest_kind: str = "config"

    def __post_init__(self) -> None:
        """Reject mutable tags and unknown digest semantics before creating an asset."""

        Digest(self.digest)

        if self.digest_kind not in {"config", "manifest"}:
            raise ValueError("image digest_kind must be config or manifest")

    def Object(self, workspace_id: str) -> ObjectIdentity:
        """Return a deterministic provider-independent ASSET identity.

        Args:
            workspace_id: Existing canonical model workspace identifier.

        Returns:
            Identity reusable by offline/runtime consumers without any authority grant.
        """

        return ObjectIdentity(workspace_id, ObjectKind.ASSET,
                              f"image-{self.digest_kind}:{self.digest}")


@dataclass(frozen=True, slots=True)
class PackageIdentity:
    """Bind a package name to installed version and distribution/architecture context."""

    ecosystem: str
    name: str
    version: str
    namespace: str = ""
    qualifiers: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        """Validate finite identity fields and freeze unique sorted qualifier names."""

        if not isinstance(self.ecosystem, str) or not _TYPE.fullmatch(self.ecosystem):
            raise ValueError("package ecosystem must be a lowercase type")

        Text(self.name)
        Text(self.version)

        if self.namespace:
            Text(self.namespace)

        qualifiers = tuple(self.qualifiers)

        if len(qualifiers) > 4 or len({key for key, _ in qualifiers}) != len(qualifiers):
            raise ValueError("package qualifiers must be finite and unique")

        for key, value in qualifiers:
            if key not in {"arch", "distro", "os", "os_version"}:
                raise ValueError("package qualifier is outside the supported identity profile")

            Text(value)

        if self.ecosystem == "pypi":
            if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?", self.name):
                raise ValueError("PyPI package names must use the canonical project-name syntax")

            object.__setattr__(self, "name", re.sub(r"[-_.]+", "-", self.name).lower())

        object.__setattr__(self, "qualifiers", tuple(sorted(qualifiers)))

    def Object(self, workspace_id: str) -> ObjectIdentity:
        """Project immutable package-version fields into the existing ASSET namespace.

        Args:
            workspace_id: Existing model workspace identifier.

        Returns:
            Version-specific identity shared across image origins and source tools.
        """

        key = hashlib.sha256(CanonicalModelJson(self)).hexdigest()

        return ObjectIdentity(workspace_id, ObjectKind.ASSET, f"package-version:{key}")

    @classmethod
    def FromPurl(cls, value: object) -> PackageIdentity:
        """Decode the bounded versioned PURL profile without network/package lookups.

        Args:
            value: Versioned PURL with only arch/distro/os/os_version qualifiers, no subpath.

        Returns:
            Decoded deterministic fields; PyPI names use its standard separator folding.

        Raises:
            ValueError: PURL syntax, percent encoding, version or qualifiers are unsupported.
        """

        text = Text(value)

        if not text.startswith("pkg:") or "#" in text or _BAD_PERCENT.search(text):
            raise ValueError("package identity requires a versioned PURL without subpath")

        body, _, query = text[4:].partition("?")
        name_path, separator, version = body.rpartition("@")
        ecosystem, slash, package_path = name_path.partition("/")

        if not separator or not slash or "@" in package_path:
            raise ValueError("package PURL requires a name and installed version")

        try:
            parts = [Text(unquote(part, errors="strict")) for part in package_path.split("/")]
            decoded_version = Text(unquote(version, errors="strict"))
            qualifiers = []

            for entry in query.split("&") if query else ():
                key, equals, qualifier = entry.partition("=")

                if not equals:
                    raise ValueError("package PURL qualifiers require key/value pairs")

                qualifiers.append((key, Text(unquote(qualifier, errors="strict"))))

        except UnicodeError as error:
            raise ValueError("package PURL encoding must be UTF-8") from error

        if any("/" in part or part in {".", ".."} for part in parts):
            raise ValueError("package PURL name components must be unambiguous")

        return cls(ecosystem, parts[-1], decoded_version, "/".join(parts[:-1]), tuple(qualifiers))


def VerifyRecords(state: ModelState, provenance: ModelProvenance,
                  records: tuple[EvidenceRecord, ...], workspace_root: Path,
                  report: AdapterReport | None = None) -> dict[str, bytes]:
    """Verify explicit manifest identities, raw bytes and attribution before interpretation.

    Args:
        state: Canonical snapshot whose workspace owns the incoming evidence.
        provenance: First-party attribution matching incoming manifest collection facts.
        records: Explicit unique-role EvidenceRecord manifests, never content-only references.
        workspace_root: Existing owned workspace; evidence is read from its canonical store.
        report: Exact native report, or None for an independently acquired offline document.

    Returns:
        Verified raw bytes by role, after every manifest and attribution check succeeds.
    """

    workspace = LocalWorkspaceStore(workspace_root)

    if not isinstance(state, ModelState) or not isinstance(provenance, ModelProvenance) or (
        not isinstance(records, tuple)
        or any(not isinstance(item, EvidenceRecord) for item in records)
    ):
        raise ValueError("image import requires typed state, attribution and evidence records")

    expected_roles = {"sbom"} if report is None else {"stdout", "stderr", "provider-version"}

    if len(records) != len(expected_roles) or {item.reference.role for item in records} != (
        expected_roles
    ) or workspace.Open().workspace_id != state.workspace_id:
        raise ValueError("image evidence requires exact source roles in the owning workspace")

    references = tuple(sorted((record.reference for record in records), key=CanonicalModelJson))

    if references != provenance.evidence_references or (report is not None and (
        references != tuple(sorted(report.evidence, key=CanonicalModelJson))
        or provenance.source_id != report.invocation.adapter_id
        or provenance.target_reference != report.invocation.request.target_reference
        or provenance.provider_version != report.invocation.provider_version
        or provenance.execution != report.execution
    )):
        raise ValueError("image model provenance differs from the attributed source report")

    store = LocalEvidenceStore(workspace.root / "evidence")
    raw: dict[str, bytes] = {}

    for record in records:
        if record.reference.size_bytes > IMAGE_IMPORT_MAX_BYTES:
            raise ValueError("image evidence exceeds its byte budget")

        verified = store.Get(record.evidence_id)

        if verified != record:
            raise ValueError("image evidence record differs from its immutable manifest")

        source = record.provenance

        if source.workspace_id != state.workspace_id or source.scope_reference != (
            provenance.scope_reference
        ) or source.source_id != provenance.source_id or source.tool_version != (
            provenance.provider_version
        ):
            raise ValueError("image evidence workspace/scope/source/version binding differs")

        if report is not None and record.reference.role != "provider-version":
            if source.invocation_sha256 != InvocationDigest(report.invocation) or (
                source.execution != report.execution
            ):
                raise ValueError("image stream provenance differs from exact invocation/execution")

            if record.reference.role == "stdout" and source.finished_at != provenance.observed_at:
                raise ValueError("image observation time differs from scan evidence collection")

        elif source.execution is not None or source.invocation_sha256 is not None:
            raise ValueError("offline document/version evidence cannot invent scan execution")

        raw[record.reference.role] = store.Read(record.reference)

    return raw


def Asset(workspace_id: str, key: str, attributes: Mapping[str, object],
          provenance: ModelProvenance) -> SecurityObject:
    """Build one bounded first-party asset interpretation with raw evidence attribution.

    Args:
        workspace_id: Canonical workspace owning this asset.
        key: Domain-separated immutable natural key.
        attributes: Explicit whitelisted interpretation, without raw provider records.
        provenance: Evidence-linked acquisition/interpretation attribution.

    Returns:
        Existing immutable ASSET object, without creating another schema or store.
    """

    return SecurityObject(ObjectIdentity(workspace_id, ObjectKind.ASSET, key),
                          attributes, (provenance,))


def ApplyBatch(state: ModelState, objects: list[SecurityObject], relations: list[Relation],
               observations: list[Observation], findings: list[Finding],
               workspace_root: Path) -> tuple[ModelState, ModelDelta]:
    """Apply one fully interpreted batch in memory while retaining canonical finding triage.

    Args:
        state: Original canonical workspace snapshot.
        objects: Fully validated attributed asset interpretations.
        relations: Relations whose endpoints exist in the completed inventory.
        observations: Whitelisted source facts with immutable provenance.
        findings: Untriaged exact-package detector interpretations.
        workspace_root: Workspace used by the existing verified Finding ingestion boundary.

    Returns:
        One atomic in-memory revision and aggregate delta ready for LocalModelStore.Save.
    """

    updated, first = state.Apply(objects=tuple(objects), relations=tuple(relations),
                                 observations=tuple(observations))
    updated, second = ApplyVerifiedFindings(updated, tuple(findings), workspace_root)
    created = set(first.created) | set(second.created)
    changed = (set(first.updated) | set(second.updated)) - created
    updated = replace(updated, revision=state.revision + bool(created or changed))

    return updated, ModelDelta(state.revision, updated.revision,
                              tuple(sorted(created)), tuple(sorted(changed)))


def PackageFields(value: PackageIdentity) -> dict[str, object]:
    """Select non-secret package identity fields without copying arbitrary provider metadata.

    Args:
        value: Validated package identity including exact installed version.

    Returns:
        Finite normalized asset attributes shared by native and SBOM imports.
    """

    return {"asset_type": "package", "ecosystem": value.ecosystem, "namespace": value.namespace,
            "name": value.name, "version": value.version, "qualifiers": dict(value.qualifiers)}


def PackageNameMatches(identity: PackageIdentity, value: object) -> bool:
    """Compare a source package name with its unqualified or namespace-qualified identity.

    Args:
        identity: Validated PURL-derived or native fallback package identity.
        value: Provider package name, including npm/Go slash or Maven colon namespaces.

    Returns:
        True only for the identity's exact name/namespace, with PyPI separator folding.
    """

    name = Text(value)

    if identity.ecosystem == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()

    candidates = {identity.name}

    if identity.namespace:
        candidates.update((f"{identity.namespace}/{identity.name}",
                           f"{identity.namespace}:{identity.name}"))

    return name in candidates


def PackageRecord(record: dict[str, object], ecosystem: str,
                  os_fields: dict[str, object]) -> PackageIdentity:
    """Bind a native package's PURL/version, using OS context for fallback identities.

    Args:
        record: Parsed native package with name/version and optional epoch/release/PURL.
        ecosystem: Native result type used only for package identities without a PURL.
        os_fields: Observed image OS family/version retained in fallback qualifier context.

    Returns:
        Exact installed package identity; contradictory PURL/native fields fail closed.
    """

    name = Text(record.get("Name"))
    version = Text(record.get("Version"))
    release = record.get("Release")
    epoch = record.get("Epoch", 0)

    if type(epoch) is not int or epoch < 0:
        raise ValueError("native package epoch requires a nonnegative integer")

    if release is not None and release != "":
        version += "-" + Text(release)

    if epoch:
        version = f"{epoch}:{version}"

    identifier = Record(record.get("Identifier", {}))
    purl = identifier.get("PURL")

    if purl is not None:
        identity = PackageIdentity.FromPurl(purl)

        if not PackageNameMatches(identity, name) or identity.version != version:
            raise ValueError("package PURL disagrees with installed name/version")

        return identity

    qualifiers = []

    for key, value in (("arch", record.get("Arch")), ("os", os_fields.get("Family")),
                       ("os_version", os_fields.get("Name"))):
        if value is not None:
            qualifiers.append((key, Text(value)))

    return PackageIdentity(ecosystem, name, version, qualifiers=tuple(qualifiers))


def LicenseObjects(workspace_id: str, package: SecurityObject, licenses: list[object],
                   provenance: ModelProvenance) -> tuple[list[SecurityObject], list[Relation]]:
    """Preserve declared license strings as attributed assets without compliance verdicts.

    Args:
        workspace_id: Canonical workspace owning the package and declarations.
        package: Already interpreted package-version asset.
        licenses: Bounded declared license identifiers/expressions.
        provenance: Source evidence attribution; declarations are not inferred permissions.

    Returns:
        Existing ASSET interpretations and RELATED_TO declaration edges.
    """

    objects = []
    relations = []

    for value in Items(licenses):
        license_text = Text(value)
        key = hashlib.sha256(license_text.encode("utf-8")).hexdigest()
        entity = Asset(workspace_id, f"license-declaration:{key}",
                       {"asset_type": "license", "expression": license_text}, provenance)
        objects.append(entity)
        relations.append(Relation(RelationKind.RELATED_TO, package.Reference(), entity.Reference(),
                                  {"association": "declared-license"}, (provenance,)))

    return objects, relations


def ApplyVerifiedTrivyImages(state: ModelState, report: AdapterReport,
                             provenance: ModelProvenance, records: tuple[EvidenceRecord, ...],
                             workspace_root: Path) -> tuple[ModelState, ModelDelta]:
    """Normalize a verified successful native image report into the existing durable model.

    Args:
        state: Canonical immutable workspace snapshot.
        report: Successful native.trivy archive report with exact invocation metadata.
        provenance: Matching first-party scope/target/source/run attribution.
        records: Explicit immutable stdout/stderr/provider-version manifest records.
        workspace_root: Owning workspace with the original evidence store.

    Returns:
        Updated in-memory snapshot and aggregate delta; no scanner or persistence writes.

    Raises:
        ValueError: Source, schema, attribution, identity or exact package correlation fails.
        EvidenceError: Source manifests or raw bytes fail integrity verification.
    """

    if report.invocation.adapter_id != "native.trivy" or report.execution.state is not (
        ExecutionState.SUCCEEDED
    ) or report.invocation.request.capability != "image.archive-vulnerabilities":
        raise ValueError("image import requires a successful attributed Trivy archive report")

    raw = VerifyRecords(state, provenance, records, workspace_root, report)

    probe_record = next(item for item in records if item.reference.role == "provider-version")
    stream_record = next(item for item in records if item.reference.role == "stdout")

    if probe_record.provenance.finished_at > stream_record.provenance.started_at:
        raise ValueError("Trivy database probe must precede the attributed scan")

    if not re.fullmatch(r"0\.75\.[0-9]+(?:[.+_-][0-9A-Za-z._-]+)?",
                        Text(provenance.provider_version)) or any(
        item.provenance.source_version != "1" for item in records
    ):
        raise ValueError("image import requires the supported observed Trivy envelope")

    version = ParseJson(raw["provider-version"], 16 * 1024)
    database = Record(version.get("VulnerabilityDB"))

    if version.get("Version") != provenance.provider_version or (
        type(database.get("Version")) is not int or cast(int, database["Version"]) < 1
    ):
        raise ValueError("Trivy image import requires matching observed provider/database metadata")

    NormalizeEvidenceTime(Text(database.get("UpdatedAt")))
    payload = ParseJson(raw["stdout"], IMAGE_IMPORT_MAX_BYTES)

    if type(payload.get("SchemaVersion")) is not int or payload["SchemaVersion"] != 2 or (
        payload.get("ArtifactType") != "container_image"
    ):
        raise ValueError("image import requires native schema 2 container_image output")

    if "Trivy" in payload and Record(payload["Trivy"]).get("Version") != version["Version"]:
        raise ValueError("native Trivy report version contradicts collected version evidence")

    metadata = Record(payload.get("Metadata"))
    image_identity = ImageIdentity(Digest(metadata.get("ImageID")))
    image = SecurityObject(image_identity.Object(state.workspace_id),
        {"asset_type": "image", "digest": image_identity.digest, "digest_kind": "config"},
        (provenance,))
    objects = [image]
    relations = []
    observations = [Observation("image-inventory", image.Reference(),
        {"provider_version": version["Version"], "database_updated_at": database["UpdatedAt"]},
        provenance)]
    findings = []
    os_fields = Record(metadata.get("OS", {}))

    if os_fields:
        family, name = Text(os_fields.get("Family")), Text(os_fields.get("Name"))
        key = hashlib.sha256(CanonicalModelJson({"family": family, "name": name})).hexdigest()
        operating_system = Asset(state.workspace_id, f"operating-system:{key}",
            {"asset_type": "operating-system", "family": family, "version": name}, provenance)
        objects.append(operating_system)
        relations.append(Relation(RelationKind.CONTAINS, image.Reference(),
                                  operating_system.Reference(), provenance=(provenance,)))

    for value in Items(metadata.get("RepoDigests", [])):
        _, separator, digest = Text(value).rpartition("@")

        if not separator:
            raise ValueError("repo digest requires an explicit digest suffix")

        manifest_identity = ImageIdentity(Digest(digest), "manifest")
        alias = SecurityObject(manifest_identity.Object(state.workspace_id),
            {"asset_type": "image", "digest": digest, "digest_kind": "manifest"}, (provenance,))
        objects.append(alias)
        relations.append(Relation(RelationKind.RELATED_TO, alias.Reference(), image.Reference(),
                                  {"association": "provider-reported-config"}, (provenance,)))

    diff_ids = [Digest(item) for item in Items(metadata.get("DiffIDs", []))]

    for digest in diff_ids:
        layer = Asset(state.workspace_id, f"image-layer-diffid:{digest}",
                      {"asset_type": "image-layer", "diff_id": digest}, provenance)
        objects.append(layer)
        relations.append(Relation(RelationKind.CONTAINS, image.Reference(), layer.Reference(),
                                  provenance=(provenance,)))

    observations.append(Observation("image-layer-order", image.Reference(),
                                    {"diff_ids": diff_ids}, provenance))

    for native in Items(payload.get("Results", [])):
        result = Record(native)
        ecosystem = Text(result.get("Type"))
        packages = []

        native_packages = result.get("Packages")

        for value in Items([] if native_packages is None else native_packages):
            package = Record(value)
            identity = PackageRecord(package, ecosystem, os_fields)
            entity = SecurityObject(identity.Object(state.workspace_id), PackageFields(identity),
                                    (provenance,))
            objects.append(entity)
            packages.append((package, identity, entity))
            relations.append(Relation(RelationKind.CONTAINS, image.Reference(), entity.Reference(),
                                      provenance=(provenance,)))
            native_licenses = package.get("Licenses")
            licenses, license_relations = LicenseObjects(state.workspace_id, entity,
                Items([] if native_licenses is None else native_licenses), provenance)
            objects.extend(licenses)
            relations.extend(license_relations)

        native_vulnerabilities = result.get("Vulnerabilities")

        for value in Items([] if native_vulnerabilities is None else native_vulnerabilities):
            vulnerability = Record(value)
            name = Text(vulnerability.get("PkgName"))
            installed = Text(vulnerability.get("InstalledVersion"))
            matches = [entity for package, identity, entity in packages if (
                PackageNameMatches(identity, name)
                and identity.version == installed
                and ("PkgID" not in vulnerability or package.get("ID") == vulnerability["PkgID"])
            )]

            if not matches or len({entity.Reference() for entity in matches}) != 1:
                raise ValueError("vulnerability requires exactly one installed package identity")

            subject = matches[0].Reference()
            vulnerability_id = Text(vulnerability.get("VulnerabilityID"))
            severity = FindingSeverity(Text(vulnerability.get("Severity")).lower())
            fixed = vulnerability.get("FixedVersion")
            remediation = Remediation(summary=f"Upgrade to {Text(fixed)}" if fixed else None)
            findings.append(Finding(subject, "supply-chain.vulnerability", vulnerability_id,
                f"{vulnerability_id} in {name} {installed}", (provenance,), severity=severity,
                remediation=remediation))
            observations.append(Observation("image-vulnerability", subject,
                {"image_reference": image.Reference(), "vulnerability_id": vulnerability_id,
                 "installed_version": installed, "fixed_version": Text(fixed) if fixed else None},
                provenance))

    return ApplyBatch(state, objects, relations, observations, findings, workspace_root)


def ApplyVerifiedCycloneDx(state: ModelState, record: EvidenceRecord,
                           provenance: ModelProvenance, image_identity: ImageIdentity,
                           workspace_root: Path) -> tuple[ModelState, ModelDelta]:
    """Import bounded CycloneDX 1.6 package/license inventory with an explicit root-hash binding.

    Args:
        state: Canonical workspace snapshot; this function creates no separate store.
        record: Explicit independently attributed SBOM evidence manifest.
        provenance: Matching offline-document context, with no invented scan execution.
        image_identity: Caller-declared config/manifest hash semantics for the container root.
        workspace_root: Workspace owning both model and original evidence bytes.

    Returns:
        Updated in-memory inventory and delta, without vulnerability/coverage verdicts.

    Raises:
        ValueError: Format/version, root binding, component/PURL or provenance is unsupported.
        EvidenceError: Source record or bytes fail immutable integrity verification.
    """

    if record.reference.role != "sbom" or provenance.execution is not None:
        raise ValueError("CycloneDX inventory requires offline sbom evidence")

    raw = VerifyRecords(state, provenance, (record,), workspace_root)["sbom"]
    payload = ParseJson(raw, IMAGE_IMPORT_MAX_BYTES)

    if payload.get("bomFormat") != "CycloneDX" or payload.get("specVersion") != "1.6" or (
        type(payload.get("version")) is not int or cast(int, payload["version"]) < 1
    ):
        raise ValueError("SBOM import supports only CycloneDX 1.6 JSON documents")

    root = Record(Record(payload.get("metadata")).get("component"))
    hashes = [Record(value) for value in Items(root.get("hashes", []))]
    roots = [Digest("sha256:" + Text(value.get("content"))) for value in hashes
             if value.get("alg") == "SHA-256"]

    if root.get("type") != "container" or roots != [image_identity.digest]:
        raise ValueError("CycloneDX container root requires exactly the explicitly bound SHA-256")

    if root.get("components") not in (None, []):
        raise ValueError("nested CycloneDX components require a separate import profile")

    image = SecurityObject(image_identity.Object(state.workspace_id),
        {"asset_type": "image", "digest": image_identity.digest,
         "digest_kind": image_identity.digest_kind}, (provenance,))
    objects = [image]
    relations = []
    references = {Text(root["bom-ref"])} if "bom-ref" in root else set()

    for value in Items(payload.get("components", [])):
        component = Record(value)
        reference = Text(component.get("bom-ref"))

        if component.get("type") not in {"library", "application", "framework"}:
            raise ValueError("CycloneDX package inventory supports library/application/framework")

        if reference in references:
            raise ValueError("CycloneDX component references must be unique")

        references.add(reference)

        if component.get("components") not in (None, []):
            raise ValueError("nested CycloneDX components require a separate import profile")

        identity = PackageIdentity.FromPurl(component.get("purl"))

        if Text(component.get("version")) != identity.version or not PackageNameMatches(
            identity, component.get("name")
        ) or ("group" in component and Text(component["group"]) != identity.namespace):
            raise ValueError("CycloneDX component and versioned PURL disagree")

        entity = SecurityObject(identity.Object(state.workspace_id), PackageFields(identity),
                                (provenance,))
        objects.append(entity)
        relations.append(Relation(RelationKind.CONTAINS, image.Reference(), entity.Reference(),
                                  provenance=(provenance,)))
        declared: list[object] = []

        for value in Items(component.get("licenses", [])):
            license_record = Record(value)

            if {"license", "expression"}.issubset(license_record):
                raise ValueError("CycloneDX license choices must not combine ID and expression")

            declared.append(Text(license_record["expression"] if "expression" in license_record
                else Record(license_record.get("license")).get("id")))

        licenses, license_relations = LicenseObjects(
            state.workspace_id, entity, declared, provenance,
        )
        objects.extend(licenses)
        relations.extend(license_relations)

    observation = Observation("image-sbom-inventory", image.Reference(),
                              {"format": "CycloneDX", "spec_version": "1.6"}, provenance)

    return ApplyBatch(state, objects, relations, [observation], [], workspace_root)
