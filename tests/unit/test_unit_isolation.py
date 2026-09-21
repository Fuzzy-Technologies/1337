"""Tests for unit isolation behavior."""

import socket

import pytest


@pytest.mark.parametrize(
    "operation",
    ["create_connection", "connect", "connect_ex"],
)
def test_RealNetworkConnectionsAreBlocked(operation):
    """Verify real network connections are blocked."""

    with pytest.raises(RuntimeError, match="must not access the network"):
        if operation == "create_connection":
            socket.create_connection(("127.0.0.1", 9))

        else:
            with socket.socket() as client:
                getattr(client, operation)(("127.0.0.1", 9))
