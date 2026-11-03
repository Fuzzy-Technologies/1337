# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Internal bounded expression matching against an explicit caller-authored license policy."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from fuzzy1337.model import CanonicalModelJson

LICENSE_POLICY_PROFILE = "spdx-expression-policy-v1"
MAX_LICENSE_EXPRESSION_BYTES = 2048
MAX_LICENSE_TOKENS = 128
MAX_LICENSE_DEPTH = 16
MAX_LICENSE_POLICY_ATOMS = 64
_IDENTIFIER = re.compile(r"[A-Za-z0-9.-]{1,128}\+?\Z")
_POLICY_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_RESERVED = {"and", "or", "with", "none", "noassertion"}


class UnsupportedLicenseExpression(ValueError):
    """Refuse grammar outside the finite interpretation profile without reflecting its text."""


def LicenseIdentifier(value: str, *, exception: bool = False) -> str:
    """Normalize one syntactic token without claiming membership of an SPDX license list.

    Args:
        value: Bounded ASCII identifier with an optional adjacent later-version suffix.
        exception: Reject the suffix on an exception identifier.

    Returns:
        Case-insensitive identifier retaining the exact suffix semantics.
    """

    normalized = value.lower()

    if not _IDENTIFIER.fullmatch(value) or normalized.removesuffix("+") in _RESERVED or (
        normalized.startswith(("licenseref-", "documentref-"))
        or (exception and value.endswith("+"))
    ):
        raise UnsupportedLicenseExpression("unsupported-expression")

    return normalized


@dataclass(frozen=True, slots=True)
class LicenseExpressionValue:
    """Retain a bounded intermediate decision and the exact syntactic atoms it consumed."""

    status: str
    atoms: frozenset[str]
    atom: str | None = None


class LicenseExpressionParser:
    """Consume the finite grammar with bounded tokens and parenthesis recursion."""

    def __init__(self, expression: str, decisions: dict[str, str]) -> None:
        """Tokenize an ASCII-space-only expression without evaluating source as Python.

        Args:
            expression: Original expression bounded before tokenization.
            decisions: Invocation-local exact normalized atom decisions.
        """

        if type(expression) is not str or not expression or (
            len(expression.encode("utf-8")) > MAX_LICENSE_EXPRESSION_BYTES
            or any(ord(character) > 126 or ord(character) < 32 for character in expression)
        ):
            raise UnsupportedLicenseExpression("unsupported-expression")

        self.tokens = re.findall(r"[^ ()]+|[()]", expression)

        if not self.tokens or len(self.tokens) > MAX_LICENSE_TOKENS:
            raise UnsupportedLicenseExpression("unsupported-expression")

        # WITH requires whitespace on both sides, unlike the AND/OR parenthesis boundary.
        for match in re.finditer(r"[^ ()]+|[()]", expression):
            if match.group() == "WITH" and (
                match.start() == 0 or match.end() == len(expression)
                or expression[match.start() - 1] != " " or expression[match.end()] != " "
            ):
                raise UnsupportedLicenseExpression("unsupported-expression")

        self.index = 0
        self.decisions = decisions

    def Take(self, expected: str) -> bool:
        """Consume one exact operator or delimiter if it is the next token.

        Args:
            expected: Implementation-owned grammar token.

        Returns:
            Whether the selected token was present and consumed.
        """

        if self.index < len(self.tokens) and self.tokens[self.index] == expected:
            self.index += 1

            return True

        return False

    def Primary(self, depth: int) -> LicenseExpressionValue:
        """Read a parenthesized choice or one exact license/exception atom.

        Args:
            depth: Active parenthesis nesting, bounded independently of token count.

        Returns:
            Finite original-atom decisions without inferring exception or version compatibility.
        """

        if depth > MAX_LICENSE_DEPTH or self.index >= len(self.tokens):
            raise UnsupportedLicenseExpression("unsupported-expression")

        if self.Take("("):
            value = self.Or(depth + 1)

            if not self.Take(")"):
                raise UnsupportedLicenseExpression("unsupported-expression")

            return value

        atom = LicenseIdentifier(self.tokens[self.index])
        self.index += 1

        if self.Take("WITH"):
            if self.index >= len(self.tokens):
                raise UnsupportedLicenseExpression("unsupported-expression")

            exception = LicenseIdentifier(self.tokens[self.index], exception=True)
            self.index += 1
            atom += " WITH " + exception

        return LicenseExpressionValue(self.decisions.get(atom, "unknown"), frozenset((atom,)), atom)

    def And(self, depth: int) -> LicenseExpressionValue:
        """Require every conjunct while retaining uncertainty for unconfigured atoms.

        Args:
            depth: Current active parenthesis nesting.

        Returns:
            Deny for a denied conjunct, allow for all allowed conjuncts, otherwise unknown.
        """

        value = self.Primary(depth)

        while self.Take("AND"):
            right = self.Primary(depth)
            states = {value.status, right.status}

            if "deny" in states:
                status = "deny"

            elif "unknown" in states:
                status = "unknown"

            else:
                status = "allow"

            value = LicenseExpressionValue(status, value.atoms | right.atoms)

        return value

    def Or(self, depth: int) -> LicenseExpressionValue:
        """Accept one configured alternative without selecting an actual license for the caller.

        Args:
            depth: Current active parenthesis nesting.

        Returns:
            Allow for an allowed alternative, deny for all denied alternatives, otherwise unknown.
        """

        value = self.And(depth)

        while self.Take("OR"):
            right = self.And(depth)
            states = {value.status, right.status}

            if "allow" in states:
                status = "allow"

            elif "unknown" in states:
                status = "unknown"

            else:
                status = "deny"

            value = LicenseExpressionValue(status, value.atoms | right.atoms)

        return value

    def Parse(self) -> LicenseExpressionValue:
        """Consume the complete supplied expression, including all denied alternatives.

        Returns:
            Complete decision and atom set; trailing or invalid source never produces a decision.
        """

        value = self.Or(0)

        if self.index != len(self.tokens):
            raise UnsupportedLicenseExpression("unsupported-expression")

        return value


@dataclass(frozen=True, slots=True)
class LicensePolicy:
    """Explicit caller decisions, separate from publisher license assertions or legal compliance."""

    policy_id: str
    allowed: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        """Validate and canonicalize the bounded policy without an implicit license database."""

        if type(self.policy_id) is not str or not _POLICY_ID.fullmatch(self.policy_id) or (
            type(self.allowed) is not tuple or type(self.denied) is not tuple
            or not 1 <= len(self.allowed) + len(self.denied) <= MAX_LICENSE_POLICY_ATOMS
        ):
            raise ValueError("invalid-license-policy")

        for name in ("allowed", "denied"):
            atoms = []

            for source in getattr(self, name):
                try:
                    value = LicenseExpressionParser(source, {}).Parse()

                except (ValueError, UnicodeError):
                    raise ValueError("invalid-license-policy") from None

                if value.atom is None or source.strip(" ") != source or (
                    "(" in source or ")" in source
                ):
                    raise ValueError("invalid-license-policy")

                atoms.append(value.atom)

            if len(set(atoms)) != len(atoms):
                raise ValueError("invalid-license-policy")

            object.__setattr__(self, name, tuple(sorted(atoms)))

        if set(self.allowed) & set(self.denied):
            raise ValueError("invalid-license-policy")

    def Description(self) -> dict[str, object]:
        """Identify the complete normalized policy and its reproducible content digest.

        Returns:
            Explicit caller ID, finite profile, normalized decisions and SHA-256 of these fields.
        """

        fields = {"profile": LICENSE_POLICY_PROFILE, "policy_id": self.policy_id,
                  "allowed": list(self.allowed), "denied": list(self.denied)}

        return {**fields, "sha256": hashlib.sha256(CanonicalModelJson(fields)).hexdigest()}


def EvaluateLicenseExpression(expression: object, policy: LicensePolicy) -> dict[str, object]:
    """Match one source expression to explicit atom decisions using SPDX operator precedence.

    Args:
        expression: Original bounded license text; no list membership or source truth is inferred.
        policy: Exact caller-authored policy, with unknown as the default for unconfigured atoms.

    Returns:
        Allow, deny or unknown with all normalized atom decisions. Unsupported syntax, scoped
        references and resource-limit excess return unknown without a partial evaluated result.
        A match establishes only this syntactic policy result, never license compliance.
    """

    if type(policy) is not LicensePolicy:
        raise ValueError("invalid-license-policy")

    decisions = {**dict.fromkeys(policy.allowed, "allow"), **dict.fromkeys(policy.denied, "deny")}

    if type(expression) is not str:
        return {"status": "unknown", "reason": "unsupported-expression", "atoms": []}

    try:
        value = LicenseExpressionParser(expression, decisions).Parse()

    except (ValueError, UnicodeError):
        return {"status": "unknown", "reason": "unsupported-expression", "atoms": []}

    return {"status": value.status,
            "reason": "unconfigured-atoms" if value.status == "unknown" else "explicit-policy",
            "atoms": [{"atom": atom, "status": decisions.get(atom, "unknown")}
                      for atom in sorted(value.atoms)]}
