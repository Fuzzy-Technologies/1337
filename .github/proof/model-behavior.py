# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0
"""Compare public SDK refusals, exact saved bytes and old-file survival on two installed wheels.

Run each wheel: python -I p67-oracle.py PINNED_FIXTURE_MODULE before|after OUTPUT_JSON
Compare the two outputs' sdk and reads arrays exactly. No test body or external service is run.
"""
import copy
from decimal import Decimal
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory

from fuzzy1337 import model
from fuzzy1337.model import (
    CanonicalModelJson, ModelProvenance, ModelReference, ModelState,
    ObjectIdentity, ObjectKind, SecurityObject,
)

PINS = {"before": "23b2d6f352a2cdbbd9028bb69b171f4c85f5a86f",
        "after": "81847ac121a3aa55a69e12e1e902a1e755eae24f"}
FIXTURE = "70ca52cd3a1fbee6583c5ceb29994bbb86471792"


def Blob(path):
    """Hash the exact tracked-file representation, not compiled bytecode."""

    body = path.read_bytes()
    return hashlib.sha1(b"blob " + str(len(body)).encode() + b"\0" + body).hexdigest()


def Error(error):
    """Retain the exact public exception type and message for differential comparison."""

    return {"type": type(error).__name__, "message": str(error)}


class WrongReference(SecurityObject):
    """Return a stable well-formed reference inconsistent with the serialized identity."""

    __slots__ = ()

    def Reference(self):
        """Preserve the same deliberate mismatch on every call."""

        return "object:" + "0" * 64


def OwnedProposal(attributes=None, wrong=False):
    """Build only explicit local model data through the ordinary public SDK."""

    source = ModelProvenance("fixture", "run:saved", "2026-11-25T12:00:00Z",
                             "scope:fixture", "target:owned")
    constructor = WrongReference if wrong else SecurityObject
    item = constructor(ObjectIdentity("fixture", ObjectKind.ASSET, "saved:owned"),
                       {} if attributes is None else attributes, (source,))
    return ModelState("fixture").Apply(objects=(item,))[0]


def Main():
    """Run existing SDK fixture constructors, then independent exact-reader corruption controls."""

    fixturePath, tag, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]).resolve()
    assert not output.exists(), "Use a fresh oracle receipt"
    assert tag in PINS and Blob(fixturePath) == FIXTURE, "Fixture source differs"
    assert Path(model.__file__).resolve().is_relative_to(Path(sys.prefix).resolve())
    assert Blob(Path(model.__file__)) == PINS[tag], "Installed model variant differs"
    spec = importlib.util.spec_from_file_location("p67_owned_wire_fixtures", fixturePath)
    assert spec and spec.loader, "Fixture must be loadable"
    fixtures = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = fixtures
    spec.loader.exec_module(fixtures)
    roles = ("state", "object", "identity", "provenance", "execution", "relation", "observation")
    scalars = ("workspace", "inherited-workspace", "duration", "revision", "exit-code",
               "source", "provider", "identity-workspace", "identity-key", "observation-kind")
    cases = [("concrete", lambda: fixtures.Proposal(), False)]

    for role in roles:
        cases.append(("compatible-" + role, lambda role=role: fixtures.Proposal(role), False))

        if role != "state":
            cases.append(("extra-" + role,
                          lambda role=role: fixtures.Proposal(role, extra=True), True))

    for field in scalars:
        cases.append(("tagged-" + field,
                      lambda field=field: fixtures.ScalarProposal(field), True))
        cases.append(("plain-" + field,
                      lambda field=field: fixtures.ScalarProposal(field, tagged=False), False))

    cases.extend((
        ("tagged-readable-attribute", lambda: fixtures.ScalarProposal("attribute"), False),
        ("stable-wrong-reference", lambda: OwnedProposal(wrong=True), True),
        ("duplicate-wire-keys", lambda: OwnedProposal({
            fixtures.TaggedKey("duplicate", 1): 1, fixtures.TaggedKey("duplicate", 2): 2,
        }), True),
        ("unicode", lambda: OwnedProposal({"text": "Straße Ελληνικά 中文 🚀"}), False),
        ("decimal-borrowed-value", lambda: OwnedProposal({"number": Decimal("0.125")}), True),
        ("nonfinite-value", lambda: OwnedProposal({"number": float("inf")}), True),
        ("surrogate", lambda: OwnedProposal({"text": "\ud800"}), True),
        ("attribute-size", lambda: OwnedProposal({"text": "x" * 65536}), True),
    ))
    sdk = []
    output.parent.mkdir(parents=True, exist_ok=True)

    with TemporaryDirectory(prefix="p67-oracle-", dir=output.parent) as work:
        root = Path(work)

        for index, (name, build, refused) in enumerate(cases):
            (root / str(index)).mkdir()
            store, initial = fixtures.Store(root / str(index))
            original = fixtures.StoredBytes(store.root)
            row = {"case": name, "construction": None, "serialization": None, "save": None}
            proposal = None

            try:
                proposal = build()
            except Exception as error:
                row["construction"] = Error(error)

            expected = None

            if proposal is not None:
                try:
                    expected = CanonicalModelJson(proposal.ToDict()) + b"\n"
                except Exception as error:
                    row["serialization"] = Error(error)

                try:
                    committed = store.Save(proposal, expected_revision=0)
                except Exception as error:
                    row["save"] = Error(error)
                else:
                    assert expected is not None, "Save accepted an unserializable proposal"
                    assert store.Open() == committed, "Successful Save must reopen identically"

            current = fixtures.StoredBytes(store.root)
            payload = (store.root / "state/model/model.json").read_bytes()
            row["unchanged"] = current == original
            row["writer_lock"] = (store.root / "state/model/.write-lock").exists()
            row["saved_sha256"] = hashlib.sha256(payload).hexdigest()
            row["serialized_sha256"] = (None if expected is None
                                        else hashlib.sha256(expected).hexdigest())
            row["readable"] = store.Open().ToDict()
            failed = row["construction"] is not None or row["save"] is not None
            assert failed is refused, name + ": unexpected admission"
            assert row["writer_lock"] is False, name + ": writer lock survived"

            if refused:
                assert row["unchanged"] and store.Open() == initial, (
                    name + ": original bytes changed"
                )
            else:
                assert expected == payload, name + ": actual serialized bytes changed"

            sdk.append(row)

        document = fixtures.Proposal().ToDict()
        reads = []
        wireCases = [("valid", CanonicalModelJson(document) + b"\n", False)]

        def Mutate(name, edit, refused=True):
            """Alter one owned JSON field without executing any provider or workflow."""

            changed = copy.deepcopy(document)
            edit(changed)
            encoded = json.dumps(changed, ensure_ascii=True, allow_nan=False,
                                 sort_keys=True, separators=(",", ":")).encode("ascii")
            wireCases.append((name, encoded + b"\n", refused))

        Mutate("revision-bool", lambda value: value.update(revision=True))
        Mutate("revision-decimal", lambda value: value.update(revision=1.0))
        Mutate("unknown-field", lambda value: value.update(unversioned=True))
        Mutate("duplicate-object", lambda value: value["objects"].append(value["objects"][0]))
        Mutate("duplicate-observation",
               lambda value: value["observations"].append(value["observations"][0]))
        Mutate("wrong-reference", lambda value:
               value["objects"][0].update(reference="object:" + "0" * 64))
        Mutate("decimal-attribute", lambda value:
               value["objects"][0]["attributes"].update(number=0.125), False)
        Mutate("negative-zero-attribute", lambda value:
               value["objects"][0]["attributes"].update(number=-0.0), False)
        Mutate("invalid-key-unicode",
               lambda value: value["objects"][0]["identity"].update(key="saved:\ud800"))

        def Dangling(value):
            """Keep the relation's own hash valid while declaring a nonexistent endpoint."""

            relation = value["relations"][0]
            relation["target_reference"] = "object:" + "0" * 64
            relation["reference"] = ModelReference("relation", {
                key: relation[key] for key in ("kind", "source_reference", "target_reference")
            })

        Mutate("dangling-endpoint", Dangling)
        payload = wireCases[0][1]
        wireCases.extend((
            ("duplicate-json-key",
             payload.replace(b'"revision":1', b'"revision":1,"revision":1', 1),
             True),
            ("invalid-utf8", b"\xff", True),
            ("nonfinite-json", b'{"revision":NaN}', True),
            ("deep-json", b"[" * 1200 + b"0" + b"]" * 1200, True),
        ))
        empty = CanonicalModelJson(ModelState("fixture").ToDict()) + b"\n"
        exact = empty + b" " * (model.MAX_MODEL_BYTES - len(empty))
        wireCases.extend((("exact-byte-bound", exact, False),
                          ("over-byte-bound", exact + b" ", True)))

        for index, (name, payload, refused) in enumerate(wireCases):
            (root / ("read-" + str(index))).mkdir()
            store, _ = fixtures.Store(root / ("read-" + str(index)))
            (store.root / "state/model/model.json").write_bytes(payload)
            before = fixtures.StoredBytes(store.root)
            row = {"case": name, "error": None, "canonical_sha256": None}

            try:
                opened = store.Open()
                canonical = CanonicalModelJson(opened.ToDict())
                row["canonical_sha256"] = hashlib.sha256(canonical).hexdigest()
            except Exception as error:
                row["error"] = Error(error)

            assert (row["error"] is not None) is refused, name + ": unexpected read admission"
            assert fixtures.StoredBytes(store.root) == before, name + ": Open changed source bytes"
            reads.append(row)

    result = {"tag": tag, "model_blob": PINS[tag], "fixture_blob": FIXTURE,
              "sdk": sdk, "reads": reads}
    output.write_text(json.dumps(result, ensure_ascii=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"tag": tag, "sdk_cases": len(sdk), "read_cases": len(reads)}))


if __name__ == "__main__":
    Main()
