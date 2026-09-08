"""Unit-test isolation guards."""

import socket
from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def deny_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Fail closed if a unit test attempts a real network connection."""

    def blocked(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("Unit tests must not access the network.")

    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(socket.socket, "connect", blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", blocked)

    yield
