import pytest
from unittest.mock import patch, MagicMock
from isis_attack.config.types import IIHConfig
from isis_attack.attacks.adjacency.adjacency_break import AdjacencyBreakAttack

@patch("isis_attack.attacks.adjacency.adjacency_break.PacketSender")
@patch("isis_attack.network.adapter.get_local_mac")
def test_adjacency_break(mock_mac, mock_sender_cls):
    mock_mac.return_value = "00:11:22:33:44:55"
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 1
    config = IIHConfig(iface="eth0", target="01:80:C2:00:00:14")
    attack = AdjacencyBreakAttack(config)
    attack.setup()
    result = attack.launch()
    assert result.success
