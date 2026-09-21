"""Unit-test isolation guards."""

import socket
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def DenyNetwork(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail closed if a unit test attempts a real network connection."""

    def Blocked(*_args: object, **_kwargs: object) -> None:
        """Provide deterministic test support for blocked."""

        raise RuntimeError("Unit tests must not access the network.")

    monkeypatch.setattr(socket, "create_connection", Blocked)
    monkeypatch.setattr(socket.socket, "connect", Blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", Blocked)

    yield
