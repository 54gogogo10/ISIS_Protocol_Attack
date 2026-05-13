import pytest
from unittest.mock import patch, MagicMock
from isis_attack.config.types import DoSConfig
from isis_attack.attacks.dos.spf_recalc import SPFRecalcAttack


@patch("isis_attack.attacks.dos.spf_recalc.PacketSender")
@patch("isis_attack.network.adapter.get_local_mac")
def test_spf_recalc(mock_mac, mock_sender_cls):
    mock_mac.return_value = "00:11:22:33:44:55"
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 10
    config = DoSConfig(iface="eth0", target="01:80:C2:00:00:14",
                       duration=0.1, lsp_change_interval=0.01)
    attack = SPFRecalcAttack(config)
    attack.setup()
    result = attack.launch()
    assert result.success
    assert "SPF 重计算" in result.details
