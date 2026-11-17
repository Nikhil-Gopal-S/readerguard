import socket

import pytest

from readerguard import ioc


@pytest.fixture(autouse=True)
def no_network_and_no_user_lists(monkeypatch, tmp_path_factory):
    """Tests never touch the network (tests that need DNS mock it) or the user's real threat-list directory."""
    def blocked(*a, **k):
        raise AssertionError("a test tried to use the network")
    monkeypatch.setattr(socket, "getaddrinfo", blocked)
    monkeypatch.setattr(socket, "create_connection", blocked)
    monkeypatch.setattr(ioc, "DEFAULT_DIR", tmp_path_factory.mktemp("ioc") / "missing")
    ioc._cache.clear()
