# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Generate bounded anonymous synthetic request previews from exact original API schemas."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from urllib.parse import quote, urlencode

from fuzzy1337.model import CanonicalModelJson
from fuzzy1337.openapi import (
    ApiImportArray,
    ApiImportContext,
    ApiImportObject,
    ApiImportPointer,
    ApiImportText,
    ApiInput,
    ApiOperation,
    DecodeApiDocument,
    ImportOpenApi,
)
from fuzzy1337.requests import BindingSource, BodyKind, InjectionLocation, RequestDigest
from fuzzy1337.scope import Target, TargetKind

API_GENERATION_PROFILE_VERSION = 1
MAX_GENERATED_SCHEMA_DEPTH = 8
MAX_GENERATED_URL_BYTES = 8 * 1024
MAX_GENERATED_HEADER_BYTES = 8 * 1024
MAX_GENERATED_BODY_BYTES = 64 * 1024
MAX_GENERATED_REQUEST_BYTES = 128 * 1024
_SCALAR_TYPES = {"string", "integer", "number", "boolean", "null"}
_ANNOTATIONS = {"title", "description", "default", "example"}
_PARAMETER_FIELDS = {
    "in", "name", "required", "description", "deprecated", "style", "explode",
    "schema", "example", "examples", "allowReserved",
}
_LEGACY_PARAMETER_FIELDS = {
    "in", "name", "required", "description", "type", "items", "collectionFormat", "default",
}
_CONTROLLED_HEADERS = {
    "host", "cookie", "set-cookie", "authorization", "proxy-authorization",
    "www-authenticate", "proxy-authenticate", "accept", "content-type", "content-length",
    "transfer-encoding", "connection", "keep-alive", "te", "trailer", "upgrade", "expect",
}
_TOKEN = r"[!#$%&'*+.^_\x60|~0-9A-Za-z-]+"
_JSON_MEDIA = re.compile(r"application/" + _TOKEN + r"\+json\Z")
_OPERATION_REFERENCE = re.compile(r"api-operation:[0-9a-f]{64}\Z")
__all__ = ["API_GENERATION_PROFILE_VERSION", "GeneratedApiRequest", "GenerateOpenApiRequest"]


def GenerationFields(record: dict[str, object], allowed: set[str]) -> None:
    """Reject consumed source fields with unimplemented meaning without echoing their names.

    Args:
        record: Already JSON-bounded original source object.
        allowed: Exact field vocabulary for the current generation context.

    Raises:
        ValueError: The source contains an unimplemented consumed field.
    """

    if set(record) - allowed:
        raise ValueError("source field is outside the synthetic generation profile")


def SyntheticText(value: object) -> str:
    """Render only the finite synthetic scalar vocabulary as deterministic ASCII text.

    Args:
        value: Generated string, finite number or boolean, never a source literal.

    Returns:
        JSON-compatible scalar spelling without quotes around strings.

    Raises:
        ValueError: Null or a structured value cannot occupy the current textual coordinate.
    """

    if isinstance(value, str):
        return value

    if isinstance(value, (bool, int, float)):
        return CanonicalModelJson(value).decode("ascii")

    raise ValueError("textual request coordinates require a supported non-null scalar")


def SyntheticItems(value: object) -> list[str]:
    """Convert a generated primitive scalar or array into finite textual members.

    Args:
        value: One generated scalar or the two-member primitive array profile.

    Returns:
        One or two scalar spellings, without URI encoding or source values.

    Raises:
        ValueError: A member is not a supported textual scalar.
    """

    return [SyntheticText(item) for item in value] if isinstance(value, list) else [
        SyntheticText(value)
    ]


@dataclass(frozen=True, slots=True)
class GeneratedApiRequest:
    """Hold one ephemeral preview; construction and identity do not grant execution authority."""

    operation: ApiOperation
    target: Target
    headers: tuple[tuple[str, str], ...]
    body: bytes = field(repr=False)

    def Reference(self) -> str:
        """Bind the actual synthetic encoding to its source operation and profile.

        Returns:
            Deterministic preview identity; this does not attest source authenticity or consent.
        """

        return RequestDigest("api-generated-request", {
            "profile_version": API_GENERATION_PROFILE_VERSION,
            "operation_reference": self.operation.Reference(),
            "target": self.target.value, "headers": self.headers,
            "body_sha256": hashlib.sha256(self.body).hexdigest(),
        })

    def Metadata(self) -> dict[str, object]:
        """Expose attribution references without copying concrete headers or body into model state.

        Returns:
            Version/source/request/target references and a synthetic body digest.
        """

        return {
            "profile_version": API_GENERATION_PROFILE_VERSION,
            "generated_request_reference": self.Reference(),
            "operation_reference": self.operation.Reference(),
            "request_reference": self.operation.template.Reference(),
            "source_digest": self.operation.source_digest,
            "source_pointer": self.operation.source_pointer,
            "method": self.operation.template.endpoint.method,
            "target_reference": self.target.Reference(),
            "body_sha256": "sha256:" + hashlib.sha256(self.body).hexdigest(),
        }


class RequestGenerationContext:
    """Own temporary original-source validation and deterministic rendering without any I/O."""

    def __init__(self, document: dict[str, object], version: str, operation: ApiOperation) -> None:
        """Bind an already imported exact document, dialect and canonical selected operation.

        Args:
            document: Strict original source tree, retained only while rendering the preview.
            version: Original supported dialect, including Swagger 2.0.
            operation: Reimported operation selected by its canonical source/context reference.
        """

        self.parser = ApiImportContext(document, version)
        self.operation = operation

    def Pointer(self, pointer: str) -> dict[str, object]:
        """Locate a trusted importer-produced source pointer without opening or fetching anything.

        Args:
            pointer: Canonical same-document pointer produced by the importer.

        Returns:
            Original object at that pointer, including any explicitly supported local reference.

        Raises:
            ValueError: The pointer does not locate an object in the exact original document.
        """

        current: object = self.parser.document

        for token in pointer[2:].split("/"):
            name = token.replace("~1", "/").replace("~0", "~")

            if isinstance(current, dict) and name in current:
                current = current[name]

            elif isinstance(current, list) and re.fullmatch(r"0|[1-9][0-9]*", name):
                current = current[int(name)]

            else:
                raise ValueError("imported source pointer does not resolve")

        return ApiImportObject(current)

    def Value(
        self, value: object, pointer: str, *, depth: int = 0, trail: tuple[str, ...] = (),
        member: int | None = None, legacy_items: bool = False,
    ) -> object:
        """Generate only after independently validating original schema assertions and item types.

        Args:
            value: Original schema object, not the importer's lossy type summary.
            pointer: Original source pointer retained during local reference resolution.
            depth: Current bounded generated schema depth.
            trail: Active reference chain inherited by child schema traversal.
            member: Synthetic primitive array member index, or None for a scalar.
            legacy_items: Whether Swagger non-body Items Object rules forbid schema references.

        Returns:
            One synthetic scalar, fixed object or homogeneous primitive array.

        Raises:
            ValueError: Types, assertions, required fields or resource bounds are unsupported.
        """

        if depth > MAX_GENERATED_SCHEMA_DEPTH or (
            legacy_items and "$ref" in ApiImportObject(value)
        ):
            raise ValueError("schema nesting or legacy items exceeds the generation profile")

        record, source, active, kind, _, _ = self.parser.Schema(value, pointer, trail)
        annotations = _ANNOTATIONS | (
            {"examples"} if self.parser.version.startswith("3.1.") else set()
        )
        annotations |= {"deprecated"} if not self.parser.legacy else set()

        if legacy_items and member is not None:
            annotations = {"default"}

        allowed = {"type"} | annotations

        if not self.parser.legacy and not self.parser.version.startswith("3.1."):
            allowed.add("nullable")

        if kind == "object":
            allowed |= {"properties", "required"}

        elif kind == "array":
            allowed.add("items")

        GenerationFields(record, allowed)

        if "type" not in record or (member is not None and kind not in _SCALAR_TYPES):
            raise ValueError("generation requires explicit types and primitive array members")

        if kind == "object":
            properties = ApiImportObject(record.get("properties"))
            required = ApiImportArray(record.get("required", []))

            if not all(isinstance(name, str) and name in properties for name in required) or (
                len(required) != len(set(required))
            ):
                raise ValueError("required fields must be unique declared properties")

            return {name: self.Value(
                properties[name], ApiImportPointer(ApiImportPointer(source, "properties"), name),
                depth=depth + 1, trail=active,
            ) for name in sorted(properties)}

        if kind == "array":
            if "items" not in record:
                raise ValueError("generation requires homogeneous primitive item schemas")

            return [self.Value(record["items"], ApiImportPointer(source, "items"),
                depth=depth + 1, trail=active, member=index, legacy_items=legacy_items)
                for index in range(2)]

        index = 0 if member is None else member

        if kind == "string":
            return "synthetic" if member is None else f"synthetic-{index}"

        if kind == "integer":
            return index + 1

        if kind == "number":
            return index + 1.5

        if kind == "boolean":
            return index == 0

        if kind == "null":
            return None

        raise ValueError("schema type is outside the generation profile")

    def Parameter(self, record: dict[str, object], pointer: str) -> tuple[ApiInput, object]:
        """Validate a complete original parameter and generate its supported synthetic value.

        Args:
            record: Effective inherited/overridden parameter from the original source.
            pointer: Canonical parameter source pointer.

        Returns:
            Existing symbolic input descriptor and generated value.

        Raises:
            ValueError: A field, controlled header, value shape or serialization is unsupported.
        """

        GenerationFields(
            record, _LEGACY_PARAMETER_FIELDS if self.parser.legacy else _PARAMETER_FIELDS,
        )
        point = self.parser.Input(record, pointer)

        if point.point.location is InjectionLocation.HEADER and (
            point.point.selector in _CONTROLLED_HEADERS
        ):
            raise ValueError("transport and authentication headers are separately owned")

        if "allowReserved" in record and point.point.location is not InjectionLocation.QUERY:
            raise ValueError("reserved expansion is only meaningful for query parameters")

        schema = {key: item for key, item in record.items() if key in {
            "type", "items", "default", "description",
        }} if self.parser.legacy else record.get("schema")
        value = self.Value(schema, pointer, legacy_items=self.parser.legacy)
        SyntheticItems(value)

        if point.value_type == "array" and point.point.location is InjectionLocation.COOKIE:
            raise ValueError("cookie arrays have no supported portable encoding")

        if self.parser.legacy and point.serialization not in {"swagger:csv", "swagger:multi"}:
            raise ValueError("legacy collection format is outside the generation profile")

        return point, value

    def LegacyForm(
        self, parameters: list[tuple[dict[str, object], str]],
    ) -> dict[str, object]:
        """Validate original Swagger formData fields and generate scalar or primitive array data.

        Args:
            parameters: Effective original parameters, including possible formData fields.

        Returns:
            Generated form field values keyed by their declared symbolic names.

        Raises:
            ValueError: A consumed field, schema/item or collection format is unsupported.
        """

        values = {}

        for record, pointer in parameters:
            if record.get("in") != "formData":
                continue

            GenerationFields(record, _LEGACY_PARAMETER_FIELDS)
            schema = {key: item for key, item in record.items() if key in {
                "type", "items", "default", "description",
            }}
            value = self.Value(schema, pointer, legacy_items=True)
            SyntheticItems(value)
            values[ApiImportText(record.get("name"))] = value

        return values

    def Body(
        self, operation: dict[str, object], parameters: list[tuple[dict[str, object], str]],
    ) -> tuple[bytes, str | None]:
        """Render the selected original body profile using generated values and controlled framing.

        Args:
            operation: Exact source operation selected through its canonical reference.
            parameters: Effective original parameters, including legacy body/formData declarations.

        Returns:
            Synthetic body bytes and controlled Content-Type, or no Content-Type for no body.

        Raises:
            ValueError: Schema, media, body type or form/multipart shape is unsupported.
        """

        kind = self.operation.template.body_kind
        media = self.operation.media_type

        if kind is BodyKind.NONE:
            return b"", None

        if self.operation.template.endpoint.method == "TRACE":
            raise ValueError("TRACE requests cannot contain a generated body")

        if media is None or (media not in {
            "application/json", "application/x-www-form-urlencoded",
            "multipart/form-data", "text/plain",
        } and not _JSON_MEDIA.fullmatch(media)):
            raise ValueError("body media token is outside the generation profile")

        legacy_form = self.parser.legacy and any(
            record.get("in") == "formData" for record, _ in parameters
        )
        generated: object

        if legacy_form:
            generated = self.LegacyForm(parameters)

        elif self.parser.legacy:
            record, pointer = next(item for item in parameters if item[0].get("in") == "body")
            GenerationFields(record, {"in", "name", "required", "description", "schema"})
            generated = self.Value(record.get("schema"), ApiImportPointer(pointer, "schema"))

        else:
            record, pointer, _ = self.parser.Resolve(operation.get("requestBody"),
                ApiImportPointer(self.operation.source_pointer, "requestBody"))
            GenerationFields(record, {"required", "description", "content"})
            content = ApiImportObject(record.get("content"))
            representation = ApiImportObject(content.get(media))
            GenerationFields(representation, {"schema", "example", "examples", "encoding"})

            if "encoding" in representation and ApiImportObject(representation["encoding"]):
                raise ValueError("custom body encodings are outside the generation profile")

            schema_pointer = ApiImportPointer(
                ApiImportPointer(ApiImportPointer(pointer, "content"), media), "schema",
            )
            generated = self.Value(representation.get("schema"), schema_pointer)

        if kind is BodyKind.JSON:
            return CanonicalModelJson(generated), media

        if kind is BodyKind.TEXT:
            if not isinstance(generated, str):
                raise ValueError("plain text bodies require a string schema")

            return generated.encode("utf-8"), media

        fields = ApiImportObject(generated)
        pairs: list[tuple[str, str]] = []

        for name in sorted(fields):
            value = fields[name]

            if isinstance(value, list):
                if not legacy_form or kind is not BodyKind.FORM:
                    raise ValueError("only legacy URL-encoded primitive form arrays are supported")

                descriptor = next(
                    item for item in self.operation.inputs
                    if item.point.location is InjectionLocation.BODY
                    and item.point.selector == name
                )

                if descriptor.serialization not in {"swagger:csv", "swagger:multi"}:
                    raise ValueError("legacy form collection format is unsupported")

                parts = SyntheticItems(value)
                if descriptor.explode:
                    pairs.extend((name, text) for text in parts)

                else:
                    pairs.append((name, ",".join(parts)))

            else:
                pairs.append((name, SyntheticText(value)))

        if kind is BodyKind.FORM:
            return urlencode(pairs).encode("ascii"), media

        if kind is not BodyKind.MULTIPART:
            raise ValueError("body encoding is outside the generation profile")

        boundary = "1337-synthetic-" + self.operation.Reference().split(":")[1][:32]
        body = b"".join(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n'
            f"Content-Type: text/plain; charset=utf-8\r\n\r\n{text}\r\n".encode("ascii")
            for name, text in pairs
        ) + f"--{boundary}--\r\n".encode("ascii")

        return body, f"{media}; boundary={boundary}"

    def Render(self) -> GeneratedApiRequest:
        """Bind effective source data and render a bounded existing exact URL Target.

        Returns:
            One anonymous synthetic preview with the canonical source operation.

        Raises:
            ValueError: Source data, security, destination or encoded byte bounds are unsupported.
        """

        if self.operation.security and not any(
            not alternative for alternative in self.operation.security
        ):
            raise ValueError("generation requires an anonymous security alternative")

        if self.operation.template.session_reference is not None or any(
            point.binding.source is not BindingSource.INPUT
            for point in self.operation.template.injection_points
        ):
            raise ValueError("synthetic generation cannot resolve session bindings")

        source = self.operation.source_pointer
        path_pointer = source.rsplit("/", 1)[0]
        operation = self.Pointer(source)
        path = self.Pointer(path_pointer)
        parameters = self.parser.Parameters(
            path.get("parameters", []), operation.get("parameters", []),
            ApiImportPointer(path_pointer, "parameters"), ApiImportPointer(source, "parameters"),
        )
        actual_path = self.operation.template.endpoint.path_template
        query: list[str] = []
        headers: list[tuple[str, str]] = []
        cookies: list[str] = []

        for record, pointer in parameters:
            if record.get("in") in {"body", "formData"}:
                continue

            descriptor, value = self.Parameter(record, pointer)
            location = descriptor.point.location
            name = descriptor.point.selector
            items = SyntheticItems(value)
            encoded = [quote(item, safe="-._~") for item in items]

            if location is InjectionLocation.PATH:
                actual_path = actual_path.replace("{" + name + "}", ",".join(encoded))

            elif location is InjectionLocation.QUERY:
                components = encoded if isinstance(value, list) and descriptor.explode else [
                    ",".join(encoded)
                ]
                query.extend(quote(name, safe="-._~") + "=" + item for item in components)

            elif location is InjectionLocation.HEADER:
                headers.append((name, ",".join(items)))

            else:
                cookies.append(quote(name, safe="-._~") + "=" + encoded[0])

        body, content_type = self.Body(operation, parameters)

        if cookies:
            headers.append(("cookie", "; ".join(cookies)))

        if content_type is not None:
            headers.append(("content-type", content_type))

        endpoint = self.operation.template.endpoint
        query_suffix = "?" + "&".join(query) if query else ""
        target = Target(TargetKind.URL, endpoint.origin + actual_path + query_suffix)
        header_bytes = sum(len(f"{name}: {value}\r\n".encode("ascii")) for name, value in headers)
        url_bytes = len(target.value.encode("utf-8"))

        if url_bytes > MAX_GENERATED_URL_BYTES or header_bytes > MAX_GENERATED_HEADER_BYTES or (
            len(body) > MAX_GENERATED_BODY_BYTES
            or url_bytes + header_bytes + len(body) > MAX_GENERATED_REQUEST_BYTES
        ):
            raise ValueError("generated request exceeds its encoded byte budget")

        return GeneratedApiRequest(self.operation, target, tuple(headers), body)


def GenerateOpenApiRequest(
    value: str, operation_reference: str, *, workspace_id: str, base_url: str | None = None,
    document_format: str = "json",
) -> GeneratedApiRequest:
    """Generate one source-bound anonymous synthetic preview without traffic or state changes.

    Args:
        value: Exact original untrusted text, never a filename or retrieval URL.
        operation_reference: Canonical source/server/media operation reference from ImportOpenApi.
        workspace_id: Explicit matching existing workspace-local owner.
        base_url: Same explicit resolution context used by the original import, when required.
        document_format: Same explicit json/yaml interpretation used by the original import.

    Returns:
        One bounded ephemeral preview with generated values and original source identity.

    Raises:
        ValueError: Operation binding, original assertions, encoding or resource limits fail.
    """

    try:
        if not isinstance(operation_reference, str) or not _OPERATION_REFERENCE.fullmatch(
            operation_reference
        ):
            raise ValueError("generation requires a canonical operation reference")

        imported = ImportOpenApi(value, workspace_id=workspace_id, base_url=base_url,
                                 document_format=document_format)
        matches = [item for item in imported.operations if item.Reference() == operation_reference]

        if len(matches) != 1:
            raise ValueError("operation reference does not match the exact source/context")

        document, version, _, _ = DecodeApiDocument(value, document_format=document_format)
        return RequestGenerationContext(document, version, matches[0]).Render()

    except (ValueError, TypeError, KeyError, IndexError, StopIteration, UnicodeError):
        raise ValueError("source is outside the bounded synthetic request profile") from None
