import pytest
from unittest.mock import patch, MagicMock
from isis_attack.config.types import MITMConfig
from isis_attack.attacks.protocol.mitm import MITMAttack


@patch("isis_attack.attacks.protocol.mitm.parse_isis_packet")
@patch("isis_attack.attacks.protocol.mitm.PacketSender")
@patch("isis_attack.attacks.protocol.mitm.Sniffer")
@patch("isis_attack.attacks.protocol.mitm.HAS_PCAP", True)
def test_mitm(mock_sniffer_cls, mock_sender_cls, mock_parse):
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 1

    mock_sniffer = MagicMock()
    mock_sniffer.available = True
    mock_sniffer.stop.return_value = [b"fake_isis_packet"]
    mock_sniffer_cls.return_value = mock_sniffer

    mock_parse.return_value = MagicMock()

    config = MITMConfig(iface="eth0", target="01:80:C2:00:00:14", action="modify")
    attack = MITMAttack(config)
    attack.setup()
    result = attack.launch()
    assert result.success
    assert "MITM" in result.details
