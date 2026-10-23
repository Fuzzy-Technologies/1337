# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Fixed material worker wire and tiny owned-file reads without scanner execution."""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace

import pytest

from fuzzy1337 import native_image_material_worker as worker
from fuzzy1337.artifact_inputs import PhysicalIdentity
from fuzzy1337.native_image_material_worker import (
    ROLE_BOUNDS,
    CanonicalControl,
    ControlIdentity,
    ObserveControl,
    ParseControl,
    ReadControl,
    SelectionFromControl,
    StrictMetadata,
)


@pytest.fixture
def material_control(tmp_path, monkeypatch):
    """Create one explicit four-file request owned entirely by this pytest fixture."""

    root = tmp_path.resolve()
    directory = root / "native-material-owned"
    directory.mkdir(mode=0o700)
    (root / "image.tar").write_bytes(b"OWNED_ARCHIVE")
    (root / "trivy").write_bytes(b"OWNED_NONEXECUTED_BINARY")
    database = root / "cache" / "db"
    database.mkdir(parents=True)
    (database / "trivy.db").write_bytes(b"OWNED_DATABASE")
    metadata = {"Version": 2, "UpdatedAt": "2026-06-22T14:30:14Z"}
    (database / "metadata.json").write_bytes(json.dumps(metadata).encode())
    info = directory.stat()
    parent = root.stat()
    value = {"schema_version": 1, "nonce": "a" * 32, "operation_reference": "pair:unit",
        "workspace_id": "workspace:unit", "owner_reference": "actor:unit",
        "read_consent": {"actor_ref": "actor:unit", "record_ref": "read:unit"},
        "selection": {"workspace_root": str(root), "executable": str(root / "trivy"),
                      "archive": "image.tar", "cache_directory": "cache"},
        "directory_identity": (info.st_dev, info.st_ino),
        "workspace_identity": (parent.st_dev, parent.st_ino), "roles": ROLE_BOUNDS}
    path = directory / "request.json"
    raw = CanonicalControl(value)
    path.write_bytes(raw)
    path.chmod(0o600)

    if os.name == "nt":
        def SimulatedMode(mode):
            """Model Linux private modes only for portable protocol units, never OS acceptance."""

            return 0o700 if stat.S_ISDIR(mode) else 0o600

        monkeypatch.setattr(worker, "stat", SimpleNamespace(S_IMODE=SimulatedMode))

    return path, hashlib.sha256(raw).hexdigest(), PhysicalIdentity(path.stat()), value


def test_FixedWorkerReadsFourOriginalRolesWithoutExecutingSelectedBinary(material_control):
    """The selected binary is ordinary inert bytes and only its exact hash is returned."""

    path, digest, identity, _ = material_control
    request = ReadControl(path, digest, identity)
    result = ParseControl(ObserveControl(request, digest, identity))
    assert [(fact["role"], fact["size_bytes"]) for fact in result["facts"]] == [
        ("archive", 13), ("executable", 24), ("database", 14), ("database-metadata", 51)
    ], "Exactly the original four roles retain the known owned byte lengths."
    assert result["facts"][0]["sha256"] == hashlib.sha256(b"OWNED_ARCHIVE").hexdigest(), (
        "Archive hash must identify actual selected bytes."
    )
    assert result["metadata"] == {"Version": 2, "UpdatedAt": "2026-06-22T14:30:14Z"}, (
        "Only strict selected metadata is returned."
    )
    assert result["request_sha256"] == digest and result["request_identity"] == list(identity), (
        "The result binds the exact physical original request."
    )


@pytest.mark.parametrize("change", [
    {"schema_version": True}, {"schema_version": 2}, {"nonce": "x" * 32},
    {"workspace_id": ""}, {"owner_reference": "other"}, {"roles": []},
    {"directory_identity": [1]}, {"workspace_identity": [True, 1]},
    {"read_consent": {}}, {"selection": {}}, {"unexpected": "NO_EXTRA_FIELDS"},
])
def test_PrivateSelectionRejectsChangedShapeConsentAndRoles(material_control, change):
    """No extra field, role, weak scalar or mismatched owner can select material."""

    _, _, _, value = material_control
    changed = ParseControl(CanonicalControl({**value, **change}))

    with pytest.raises(ValueError):
        SelectionFromControl(changed)


@pytest.mark.parametrize("raw", [b'{} ', b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'\xff'])
def test_PrivateWireRejectsAmbiguousNoncanonicalAndNonfiniteBytes(raw):
    """Private framing admits one canonical finite object only."""

    with pytest.raises(ValueError):
        ParseControl(raw)


@pytest.mark.parametrize("value", [None, [], [1] * 6, [True] * 5, [-1] * 5, [1.0] * 5])
def test_PrivateIdentityRequiresExactObservedIntegerTuple(value):
    """Booleans and coercible scalar values are never physical identity facts."""

    with pytest.raises(ValueError):
        ControlIdentity(value)


@pytest.mark.parametrize("metadata", [
    {}, {"Version": True, "UpdatedAt": "2026-01-01T00:00:00Z"},
    {"Version": 1, "UpdatedAt": "2026-01-01T00:00:00Z"},
    {"Version": 2, "UpdatedAt": "2026-01-01T00:00:00"},
    {"Version": 2, "UpdatedAt": "invalid"},
])
def test_MetadataRequiresStrictSchemaTwoAndTimezone(metadata):
    """A database presence or checksum cannot manufacture valid schema-two metadata."""

    with pytest.raises(ValueError):
        StrictMetadata(json.dumps(metadata).encode())


def test_PrivateControlBoundAndPhysicalSubstitutionAreRejected(material_control):
    """The original request digest and opened identity both matter independently."""

    path, digest, identity, _ = material_control

    with pytest.raises(ValueError):
        CanonicalControl({"too_large": "x" * (64 * 1024)})

    with pytest.raises(ValueError):
        ReadControl(path, "0" * 64, identity)

    with pytest.raises(ValueError):
        ReadControl(path, digest, (*identity[:2], identity[2] + 1, *identity[3:]))

    if os.name != "nt":
        path.chmod(0o644)

        with pytest.raises(ValueError):
            ReadControl(path, digest, PhysicalIdentity(path.stat()))


def test_MissingDatabaseRemainsMissingFactsAndNoMetadata(material_control):
    """The worker describes absence without inventing a usable complete material proof."""

    path, digest, identity, _ = material_control
    database = path.parent.parent / "cache" / "db"
    (database / "trivy.db").unlink()
    (database / "metadata.json").unlink()
    result = ParseControl(ObserveControl(ReadControl(path, digest, identity), digest, identity))
    assert result["metadata"] is None, "Missing metadata must remain missing."
    assert all(fact["sha256"] is None for fact in result["facts"][2:]), (
        "Missing database roles cannot become fabricated hashes."
    )


def test_InstalledEntryUsesOnlyFixedArgumentsAndBoundedDiagnostic(material_control, monkeypatch):
    """The entry point writes private JSON or a fixed refusal without selected file content."""

    path, digest, identity, _ = material_control
    output = io.BytesIO()
    errors = io.StringIO()
    monkeypatch.setattr(worker, "sys", SimpleNamespace(platform="linux",
        stdout=SimpleNamespace(buffer=output), stderr=errors))
    assert worker.Main([str(path), digest, ",".join(map(str, identity))]) == 0, (
        "The fixed owned request can be observed without invoking its selected binary."
    )
    assert ParseControl(output.getvalue())["request_sha256"] == digest, (
        "Private output binds its original request."
    )
    assert worker.Main([]) == 2, "Missing fixed arguments must fail closed."
    assert errors.getvalue() == "native-material-observation-refused\n", (
        "A bounded fixed diagnostic cannot expose selected content."
    )


def test_MetadataReplacementAfterFactHashIsRefused(material_control, monkeypatch):
    """A subsequent selected metadata read must agree with its original fact hash."""

    path, digest, identity, _ = material_control
    original = worker.NativeTrivySelection.Material

    def Changed(selection):
        """Mutate only this tiny pytest-owned metadata after original hashing completes."""

        facts = original(selection)
        Path(facts[-1].path).write_bytes(b'{"Version":2,"UpdatedAt":"2027-01-01T00:00:00Z"}')

        return facts

    monkeypatch.setattr(worker.NativeTrivySelection, "Material", Changed)

    with pytest.raises(ValueError, match="changed"):
        ObserveControl(ReadControl(path, digest, identity), digest, identity)
