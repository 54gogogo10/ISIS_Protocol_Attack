import pytest
from unittest.mock import patch, MagicMock
from isis_attack.config.types import DoSConfig
from isis_attack.attacks.dos.flood import FloodAttack


@patch("isis_attack.attacks.dos.flood.PacketSender")
@patch("isis_attack.network.adapter.get_local_mac")
def test_flood(mock_mac, mock_sender_cls):
    mock_mac.return_value = "00:11:22:33:44:55"
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 1
    config = DoSConfig(iface="eth0", target="01:80:C2:00:00:14", duration=0.1)
    attack = FloodAttack(config)
    attack.setup()
    result = attack.launch()
    assert result.success
    assert "泛洪攻击" in result.details
