# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Source-only seam reusing the reviewed original IPv4 native-state seed, never acquisition.

This first setup seam deliberately refuses IPv6: the byte-identical original seed registers
IPv4. A separate reviewed setup is required before an IPv6 SDK case can be enrolled.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from types import ModuleType

OWNER = "actor:owned-response-product"
ATTESTER = "attester:independent-source-consent"
WORKSPACE = "owned-response-product"
SCOPE = "owned-source"
MAX_SEED_SOURCE_BYTES = 1024 * 1024


def LoadSeed() -> tuple[ModuleType, dict]:
    """Load only the fixed reviewed original Setup/Inspect bytes, with separate source binding.

    Returns:
        Original helper namespace and observed exact source path/hash. The caller must reconcile
        this observation against its reviewed checkpoint before authorizing actual setup.
    """

    path = Path(__file__).resolve().with_name("owned_response_product_runner.py")

    with path.open("rb") as stream:
        raw = stream.read(MAX_SEED_SOURCE_BYTES + 1)

    if len(raw) > MAX_SEED_SOURCE_BYTES:
        raise ValueError("Fixed reviewed original seed source exceeds its byte ceiling")

    module = ModuleType("owned_content_response_original_seed")
    module.__file__ = str(path)
    exec(compile(raw, str(path), "exec"), module.__dict__)

    return module, {"path": str(path), "sha256": hashlib.sha256(raw).hexdigest()}


def Setup(config: dict, *, enabled: bool = False) -> dict:
    """Create one fresh explicitly selected owned IPv4 SDK workspace with original native triage.

    Args:
        config: Exactly absolute workspace, canonical literal content URL and fixed seed owner.
        enabled: Independent exact execution opt-in; false performs no reads or store activity.

    Returns:
        Actual original Setup/Inspect values unchanged, plus explicit later SDK selection and
        observed fixed helper hash. This is not acquisition, consent verification or acceptance.
    """

    if enabled is not True:
        raise PermissionError("Fresh owned SDK setup requires explicit execution opt-in")

    if type(config) is not dict or set(config) != {"workspace", "url", "owner_reference"} or (
        any(type(value) is not str or not value for value in config.values())
    ):
        raise ValueError("Fresh SDK setup requires its entire explicit selection")

    root = Path(config["workspace"])

    if not root.is_absolute() or ".." in root.parts or config["owner_reference"] != OWNER:
        raise ValueError("Fresh SDK setup requires its absolute workspace and original fixed actor")

    from fuzzy1337.adapters.owned_content_response import Destination

    address, _port, _path, _authority = Destination(config["url"])

    if address != "127.0.0.1":
        raise ValueError("The reviewed original seed supports only explicitly selected IPv4")

    if root.exists() or root.is_symlink():
        raise FileExistsError("Fresh SDK setup refuses an existing workspace without changing it")

    original, source = LoadSeed()

    if original.OWNER != OWNER or original.WORKSPACE != WORKSPACE or OWNER == ATTESTER:
        raise ValueError("Reviewed original actor/workspace bindings changed")

    # Original Create owns its atomic absent-root mkdir; precreating it would defeat that contract.
    actual = original.Setup({"workspace": str(root), "url": config["url"]})

    return {"selection": {"workspace": str(root), "url": config["url"], "ip": address,
        "scope_id": SCOPE, "owner_reference": OWNER, "attester_reference": ATTESTER},
        "original_setup": actual, "seed_source": source}
