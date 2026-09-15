"""The GUI exception must never enable unrelated legacy ACP operations."""
from unittest.mock import Mock

import pytest

from timecapsulesmb.integrations import acp


def test_scope_allows_only_two_writes_and_resets_on_failure(monkeypatch):
    monkeypatch.delenv("TCAPSULE_ALLOW_INSECURE_ACP", raising=False)
    open_connection = Mock()
    monkeypatch.setattr(acp, "_open_connection", open_connection)
    payload = acp._compose_property_element("dbug", acp.DBUG_SSH_VALUE)

    def send(host="device", command=acp.COMMAND_SETPROP, data=payload, flags=0):
        return acp._send_message(host, "private-password", command, data, flags=flags, timeout=1)

    with pytest.raises(acp.ACPSecurityError):
        send()
    open_connection.assert_not_called()
    with pytest.raises(RuntimeError):
        with acp.confirmed_ssh_setup("device"):
            send()
            send(data=acp._compose_property_element("acRB", 0))
            for kwargs in (
                {"host": "other"}, {"command": acp.COMMAND_FLASH_PRIMARY},
                {"command": acp.COMMAND_FLASH_SECONDARY}, {"command": acp.COMMAND_GETPROP},
                {"data": acp._compose_property_element("dbug", 0)},
                {"data": payload + acp._compose_property_element("acRB", 0)}, {"flags": 1},
            ):
                with pytest.raises(acp.ACPSecurityError):
                    send(**kwargs)
            raise RuntimeError("cancelled")
    assert open_connection.call_count == 2
    with pytest.raises(acp.ACPSecurityError):
        send()

