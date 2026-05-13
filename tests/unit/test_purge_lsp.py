import pytest
from unittest.mock import patch, MagicMock
from isis_attack.config.types import LSPConfig
from isis_attack.attacks.lsp.purge_lsp import PurgeLSPAttack


@patch("isis_attack.attacks.lsp.purge_lsp.PacketSender")
@patch("isis_attack.network.adapter.get_local_mac")
def test_purge_lsp(mock_mac, mock_sender_cls):
    mock_mac.return_value = "00:11:22:33:44:55"
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 1
    config = LSPConfig(iface="eth0", target="01:80:C2:00:00:14", sys_id="1921.6800.9999")
    attack = PurgeLSPAttack(config)
    attack.setup()
    result = attack.launch()
    assert result.success
    assert "LSP 清除" in result.details
