import pytest
from unittest.mock import patch, MagicMock
from isis_attack.config.types import LSPConfig
from isis_attack.attacks.lsp.fight_back import FightBackAttack


@patch("isis_attack.attacks.lsp.fight_back.PacketSender")
@patch("isis_attack.network.adapter.get_local_mac")
def test_fight_back(mock_mac, mock_sender_cls):
    mock_mac.return_value = "00:11:22:33:44:55"
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 0
    config = LSPConfig(iface="eth0", target="01:80:C2:00:00:14",
                       sys_id="1921.6800.9999", metric=50, network_addr="10.99.0.0")
    attack = FightBackAttack(config)
    assert attack.needs_repeated is True
    attack.setup()
    assert attack._seq == 1
    result = attack.launch()
    assert result.success
    assert "Fight-Back" in result.details
    assert attack._seq == 2
