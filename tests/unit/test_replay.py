import pytest
from unittest.mock import patch, MagicMock
from isis_attack.config.types import ReplayConfig
from isis_attack.attacks.protocol.replay import ReplayAttack


@patch("isis_attack.attacks.protocol.replay.rdpcap")
@patch("isis_attack.attacks.protocol.replay.PacketSender")
def test_replay(mock_sender_cls, mock_rdpcap):
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 3

    mock_rdpcap.return_value = [MagicMock(), MagicMock(), MagicMock()]

    config = ReplayConfig(iface="eth0", target="01:80:C2:00:00:14",
                          capture_file="test.pcap")
    attack = ReplayAttack(config)
    attack.setup()
    result = attack.launch()
    assert result.success
    assert "重放" in result.details
    assert result.packets_sent > 0
