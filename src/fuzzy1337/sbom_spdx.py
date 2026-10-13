# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Experimental verified offline SPDX 2.3 package inventory through existing image contracts."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from fuzzy1337.adapters.trivy import ParseJson
from fuzzy1337.evidence import EvidenceRecord, NormalizeEvidenceTime
from fuzzy1337.images import (
    IMAGE_IMPORT_MAX_BYTES,
    ApplyBatch,
    Digest,
    ImageIdentity,
    Items,
    LicenseObjects,
    PackageFields,
    PackageIdentity,
    PackageNameMatches,
    Record,
    Text,
    VerifyRecords,
)
from fuzzy1337.model import (
    ModelDelta,
    ModelProvenance,
    ModelState,
    Observation,
    Relation,
    RelationKind,
    SecurityObject,
)

SPDX_IMPORT_VERSION = 1
_DOCUMENT = "SPDXRef-DOCUMENT"
_ID = re.compile(r"SPDXRef-[A-Za-z0-9.-]{1,128}\Z")
_UNSUPPORTED = (
    "files", "snippets", "annotations", "externalDocumentRefs", "hasExtractedLicensingInfos",
    "signatures", "vulnerabilities", "vex",
)
__all__ = ["SPDX_IMPORT_VERSION", "ApplyVerifiedSpdx"]


def SpdxIdentifier(value: object, *, document: bool = False) -> str:
    """Require one bounded local identifier without resolving external SPDX documents.

    Args:
        value: Supplied structural identifier, never a retrieval URL.
        document: Whether the reserved document identifier is permitted.

    Returns:
        Validated local SPDX identifier unchanged.
    """

    if not isinstance(value, str) or not _ID.fullmatch(value) or (
        value == _DOCUMENT and not document
    ):
        raise ValueError("SPDX identifiers must be bounded, local and unique")

    return value


def SpdxJson(raw: bytes) -> dict[str, object]:
    """Reuse strict JSON budgets and reject unpaired Unicode even in ignored fields.

    Args:
        raw: Verified original document bytes, not a filename or retrieval address.

    Returns:
        Strict finite JSON object with valid Unicode keys and string values.
    """

    try:
        payload = ParseJson(raw, IMAGE_IMPORT_MAX_BYTES)
        pending: list[object] = [payload]

        while pending:
            value = pending.pop()

            if isinstance(value, dict):
                pending.extend(value.keys())
                pending.extend(value.values())

            elif isinstance(value, list):
                pending.extend(value)

            elif isinstance(value, str):
                value.encode("utf-8")

    except (ValueError, UnicodeError):
        raise ValueError("SPDX inventory requires strict bounded UTF-8 JSON") from None

    return payload


def SpdxUnsupported(record: dict[str, object]) -> None:
    """Reject nonempty semantic graphs instead of silently flattening their meaning.

    Args:
        record: Consumed document or package fields within the source JSON budget.
    """

    for name in _UNSUPPORTED:
        if name in record and Items(record[name]):
            raise ValueError("SPDX file/external/annotation/security graphs are unsupported")


def SpdxHeader(payload: dict[str, object]) -> None:
    """Validate the supported envelope without retaining private creation or namespace material.

    Args:
        payload: Already strictly decoded and byte/node/depth-bounded document.
    """

    if payload.get("spdxVersion") != "SPDX-2.3" or payload.get("dataLicense") != "CC0-1.0" or (
        payload.get("SPDXID") != _DOCUMENT
    ):
        raise ValueError("SPDX inventory requires the SPDX-2.3 JSON document envelope")

    Text(payload.get("name"))
    namespace = Text(payload.get("documentNamespace"))

    try:
        parsed = urlsplit(namespace)

        if not parsed.scheme or "#" in namespace or any(char.isspace() for char in namespace):
            raise ValueError("unsupported SPDX namespace")

        if parsed.scheme in {"http", "https"} and (not parsed.netloc or not parsed.hostname):
            raise ValueError("unsupported SPDX namespace authority")

        parsed.port

    except ValueError:
        raise ValueError("SPDX namespace must be an absolute URI without a fragment") from None

    creation = Record(payload.get("creationInfo"))
    created = Text(creation.get("created"))

    try:
        if not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", created):
            raise ValueError("unsupported SPDX creation time")

        NormalizeEvidenceTime(created)

    except (ValueError, OverflowError):
        raise ValueError("SPDX creation time requires a valid UTC datetime") from None

    creators = Items(creation.get("creators"))

    if not creators or any(not Text(value).startswith(("Person: ", "Organization: ", "Tool: "))
                           for value in creators):
        raise ValueError("SPDX requires bounded creator declarations")

    SpdxUnsupported(payload)


def SpdxPurl(record: dict[str, object], *, root: bool = False) -> PackageIdentity | None:
    """Bind one versioned package reference without importing CPE/URL/security links as findings.

    Args:
        record: Consumed package fields with explicit local source identity.
        root: True for the caller-bound image root, whose OCI PURL is unsupported.

    Returns:
        Existing canonical package identity, or None for the image root.
    """

    purls = []

    for value in Items(record.get("externalRefs", [])):
        reference = Record(value)
        category = Text(reference.get("referenceCategory"))
        reference_type = Text(reference.get("referenceType"))

        if reference_type == "purl":
            if category != "PACKAGE-MANAGER":
                raise ValueError("SPDX PURL references require PACKAGE-MANAGER category")

            purls.append(PackageIdentity.FromPurl(reference.get("referenceLocator")))

    if root:
        if purls:
            raise ValueError("SPDX image root PURLs require a separate OCI identity profile")

        return None

    if len(purls) != 1:
        raise ValueError("SPDX package inventory requires exactly one versioned PURL")

    identity = purls[0]

    if not PackageNameMatches(identity, record.get("name")) or Text(record.get("versionInfo")) != (
        identity.version
    ):
        raise ValueError("SPDX package name/version disagrees with its PURL")

    return identity


@dataclass(frozen=True, slots=True)
class SpdxCatalog:
    """Internal validated source graph; document identities never replace canonical model keys."""

    root_id: str
    packages: dict[str, dict[str, object]]


def SpdxGraph(payload: dict[str, object], image_identity: ImageIdentity) -> SpdxCatalog:
    """Require one described image and explicit complete flat package containment.

    Args:
        payload: Supported strictly decoded SPDX document.
        image_identity: Caller-declared config/manifest checksum interpretation.

    Returns:
        Validated local package catalog and the unique checksum-bound image root.
    """

    packages = {}

    for value in Items(payload.get("packages")):
        package = Record(value)
        identifier = SpdxIdentifier(package.get("SPDXID"))

        if identifier in packages or package.get("filesAnalyzed") is not False or any(
            name in package for name in (
                "hasFiles", "packageVerificationCode", "licenseInfoFromFiles",
            )
        ):
            raise ValueError("SPDX package identifiers must be unique with filesAnalyzed false")

        Text(package.get("name"))
        Text(package.get("downloadLocation"))
        SpdxUnsupported(package)
        packages[identifier] = package

    declared = [SpdxIdentifier(value) for value in Items(payload.get("documentDescribes", []))]

    if len(set(declared)) != len(declared):
        raise ValueError("SPDX described roots must be unique")

    described = set(declared)
    containment = set()
    relationships = set()

    for value in Items(payload.get("relationships", [])):
        relation = Record(value)
        source = SpdxIdentifier(relation.get("spdxElementId"), document=True)
        target = SpdxIdentifier(relation.get("relatedSpdxElement"), document=True)
        kind = Text(relation.get("relationshipType"))

        if kind in {"DESCRIBED_BY", "CONTAINED_BY"}:
            source, target = target, source
            kind = {"DESCRIBED_BY": "DESCRIBES", "CONTAINED_BY": "CONTAINS"}[kind]

        coordinate = source, kind, target

        if coordinate in relationships or source == target or any(
            endpoint not in packages and endpoint != _DOCUMENT for endpoint in (source, target)
        ):
            raise ValueError("SPDX relationships must be unique, local and resolved")

        relationships.add(coordinate)

        if kind == "DESCRIBES" and source == _DOCUMENT and target in packages:
            described.add(target)

        elif kind == "CONTAINS" and source in packages and target in packages:
            containment.add((source, target))

        else:
            raise ValueError("SPDX supports document description and flat containment only")

    if len(described) != 1 or (declared and set(declared) != described):
        raise ValueError("SPDX inventory requires one consistently described container root")

    root_id = next(iter(described))

    if root_id not in packages or packages[root_id].get("primaryPackagePurpose") != "CONTAINER":
        raise ValueError("SPDX described root must resolve to a CONTAINER package")

    if any(package.get("primaryPackagePurpose") == "CONTAINER" for identifier, package
           in packages.items() if identifier != root_id) or containment != {
        (root_id, identifier) for identifier in packages if identifier != root_id
    }:
        raise ValueError("SPDX packages require explicit complete flat image containment")

    hashes = []

    for value in Items(packages[root_id].get("checksums")):
        checksum = Record(value)

        if Text(checksum.get("algorithm")) == "SHA256":
            hashes.append(Digest("sha256:" + Text(checksum.get("checksumValue"))))

    if hashes != [image_identity.digest]:
        raise ValueError("SPDX root requires one explicitly bound SHA256 checksum")

    return SpdxCatalog(root_id, packages)


def SpdxLicense(value: object, *, present: bool) -> dict[str, object]:
    """Preserve license information states without evaluating or conflating source roles.

    Args:
        value: Bounded declared/concluded expression or an SPDX information-state sentinel.
        present: Whether the source field is present rather than omitted.

    Returns:
        Non-secret information-state/expression metadata, without compliance conclusions.
    """

    if not present:
        return {"state": "absent"}

    text = Text(value)

    if "licenseref-" in text.casefold() or "documentref-" in text.casefold():
        raise ValueError("SPDX scoped license references require a separate identity profile")

    if text in {"NONE", "NOASSERTION"}:
        return {"state": text.lower()}

    return {"state": "expression", "expression": text}


def ApplyVerifiedSpdx(state: ModelState, record: EvidenceRecord,
                      provenance: ModelProvenance, image_identity: ImageIdentity,
                      workspace_root: Path) -> tuple[ModelState, ModelDelta]:
    """Interpret verified SPDX package inventory through the existing image/model boundaries.

    Args:
        state: Canonical owning workspace snapshot, not a separate SBOM database.
        record: Explicit independently acquired immutable sbom evidence manifest.
        provenance: Matching acquisition context without an invented execution outcome.
        image_identity: Explicit caller-declared config/manifest root checksum semantics.
        workspace_root: Owned workspace whose evidence store verifies the original bytes.

    Returns:
        One immutable model transition preserving raw evidence and existing finding disposition.

    Raises:
        ValueError: Profile, graph, package identity, provenance or licensing is unsupported.
        EvidenceError: The immutable evidence manifest or bytes fail integrity verification.
    """

    if not isinstance(record, EvidenceRecord) or not isinstance(provenance, ModelProvenance) or (
        not isinstance(image_identity, ImageIdentity) or provenance.execution is not None
        or record.reference.role != "sbom"
    ):
        raise ValueError("SPDX inventory requires typed offline evidence and image identity")

    raw = VerifyRecords(state, provenance, (record,), workspace_root)["sbom"]

    payload = SpdxJson(raw)
    SpdxHeader(payload)
    catalog = SpdxGraph(payload, image_identity)
    image = SecurityObject(image_identity.Object(state.workspace_id), {
        "asset_type": "image", "digest": image_identity.digest,
        "digest_kind": image_identity.digest_kind,
    }, (provenance,))
    objects = [image]
    relations = []
    observations = []

    for identifier in sorted(catalog.packages):
        package = catalog.packages[identifier]
        identity = SpdxPurl(package, root=identifier == catalog.root_id)
        entity = image if identity is None else SecurityObject(
            identity.Object(state.workspace_id), PackageFields(identity), (provenance,),
        )

        if identity is not None:
            objects.append(entity)
            relations.append(Relation(RelationKind.CONTAINS, image.Reference(), entity.Reference(),
                                      provenance=(provenance,)))

        declared = SpdxLicense(package.get("licenseDeclared"), present="licenseDeclared" in package)
        concluded = SpdxLicense(
            package.get("licenseConcluded"), present="licenseConcluded" in package,
        )
        alias = {"document_sha256": record.reference.sha256, "spdx_id": identifier,
                 "image_reference": image.Reference()}
        observations.append(Observation("spdx-source-alias", entity.Reference(), alias, provenance))
        observations.append(Observation("spdx-package-license", entity.Reference(), {
            **alias, "declared": declared, "concluded": concluded,
        }, provenance))

        if declared["state"] == "expression":
            licenses, links = LicenseObjects(state.workspace_id, entity,
                                            [declared["expression"]], provenance)
            objects.extend(licenses)
            relations.extend(links)

    observations.append(Observation("image-sbom-inventory", image.Reference(),
                                   {"format": "SPDX", "spec_version": "2.3"}, provenance))

    return ApplyBatch(state, objects, relations, observations, [], workspace_root)
