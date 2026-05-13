import pytest
from unittest.mock import patch, MagicMock
from isis_attack.network.sender import PacketSender

def test_sender_init():
    s = PacketSender(iface="eth0", packet_rate=10, max_packets=100)
    assert s.iface == "eth0"
    assert s.packet_rate == 10
    assert s.max_packets == 100
    assert s.sent_count == 0

@patch("isis_attack.network.sender.sendp")
def test_send_l2(mock_sendp):
    s = PacketSender(iface="eth0", packet_rate=100)
    ok = s.send_l2("fake_packet")
    assert ok is True
    assert mock_sendp.called
    assert s.sent_count == 1

def test_rate_limit():
    s = PacketSender(iface="eth0", packet_rate=100, max_packets=2)
    assert s._rate_limit() is True
    s._inc_count()
    assert s._rate_limit() is True
    s._inc_count()
    assert s._rate_limit() is False
