# SPDX-FileCopyrightText: 2026 Timur Gilmullin and Fuzzy Technologies
# SPDX-License-Identifier: Apache-2.0

"""Own temporary file-access targets independently of scanner and expected-result assertions."""

from __future__ import annotations

import importlib.util
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event, Thread
from types import ModuleType
from typing import Any, cast

PACK = Path(__file__).parents[1] / "labs/targets/web-file-access"


def Oracle() -> dict[str, Any]:
    """Read expected cases without executing the target or deriving truth from its behavior."""

    return cast(dict[str, Any], json.loads((PACK / "oracle.v1.json").read_text(encoding="utf-8")))


def TargetModule() -> ModuleType:
    """Load the repository-owned implementation without starting a standalone public service."""

    spec = importlib.util.spec_from_file_location("owned_web_file_access", PACK / "server.py")
    assert spec is not None and spec.loader is not None, "Owned file target source must load"
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    return module


@dataclass
class WebFileAccessTarget:
    """Expose declared URLs, the owned temporary root and independent mechanism observations."""

    root: Path
    base_url: str
    server: Any
    thread: Thread

    def Url(self, case: str | dict[str, Any]) -> str:
        """Select a declared case without expanding input or granting scanner permission."""

        cases = Oracle()["cases"]

        if isinstance(case, str):
            selected = next((item for item in cases if item["id"] == case), None)

        else:
            selected = next((item for item in cases if item == case), None)

        if selected is None:
            raise ValueError("Owned file target URL requires a declared oracle case")

        return self.base_url + str(selected["route"])

    def Observe(self) -> dict[str, list[Any]]:
        """Copy actual target-side requests and file facts without reading scanner evidence."""

        return cast(dict[str, list[Any]], self.server.state.Observe())


@contextmanager
def OwnedWebFileAccessTarget(tmp_path: Path | None = None) -> Iterator[WebFileAccessTarget]:
    """Own synthetic files, loopback listener, readiness and cleanup even after partial input."""

    if tmp_path is not None:
        if tmp_path.is_symlink():
            raise ValueError("Owned target parent cannot be a symbolic link")

        tmp_path.mkdir(parents=True, exist_ok=True)

    module = TargetModule()

    with TemporaryDirectory(prefix="web-file-access-", dir=tmp_path) as temporary:
        root = Path(temporary)
        (root / "public").mkdir()
        (root / "private").mkdir()
        (root / "public/hello.txt").write_bytes(module.PUBLIC_BYTES)
        (root / "private/canary.txt").write_bytes(module.PRIVATE_BYTES)
        server = module.FileAccessServer(root)
        ready = Event()

        def Serve() -> None:
            """Run bounded HTTP dispatch without depending on BaseServer private shutdown state."""

            ready.set()

            try:
                while not server.closing.is_set():
                    server.handle_request()

            except (OSError, ValueError):
                if not server.closing.is_set():
                    server.state.Record("errors", "listener-failure")

            except Exception:
                server.state.Record("errors", "listener-failure")

        thread = Thread(target=Serve, name="owned-web-file-access-target", daemon=False)
        target = WebFileAccessTarget(root, f"http://127.0.0.1:{server.server_port}", server, thread)

        try:
            thread.start()
            assert ready.wait(2) and thread.is_alive(), "Owned file listener did not become ready"

            yield target

        finally:
            server.CloseActiveRequests()
            server.server_close()

            if thread.ident is not None:
                thread.join(timeout=3)

            assert not thread.is_alive(), "Owned file target leaked its service thread"
