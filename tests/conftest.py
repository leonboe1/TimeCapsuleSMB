from __future__ import annotations

from unittest import mock

import pytest


@pytest.fixture(autouse=True)
def block_unmocked_telemetry_posts(monkeypatch: pytest.MonkeyPatch):
    urlopen_mock = mock.Mock(side_effect=AssertionError("tests must not send telemetry"))
    monkeypatch.setattr("urllib.request.urlopen", urlopen_mock)
    yield
    urlopen_mock.assert_not_called()


@pytest.fixture(autouse=True)
def block_unmocked_ssh_connections(monkeypatch: pytest.MonkeyPatch):
    spawn_mock = mock.Mock(side_effect=AssertionError("unit tests must mock SSH connections"))
    monkeypatch.setattr("pexpect.spawn", spawn_mock)
    yield
    spawn_mock.assert_not_called()
