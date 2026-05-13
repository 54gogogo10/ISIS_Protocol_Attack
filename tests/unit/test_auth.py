import pytest
from isis_attack.core.auth import AUTH_NONE, AUTH_PLAIN, AUTH_MD5, build_auth_tlv, AUTH_TLV_PLAIN, AUTH_TLV_CRYPTO

def test_auth_constants():
    assert AUTH_NONE == 0
    assert AUTH_PLAIN == 1
    assert AUTH_MD5 == 2

def test_build_auth_none():
    tlv = build_auth_tlv(AUTH_NONE, b"")
    assert tlv == b""

def test_build_auth_plain():
    tlv = build_auth_tlv(AUTH_PLAIN, b"secret")
    assert tlv[0] == AUTH_TLV_PLAIN  # type 10
    assert tlv[1] == 6  # length
    assert tlv[2:] == b"secret"

def test_build_auth_md5():
    tlv = build_auth_tlv(AUTH_MD5, b"mykey", pdu_bytes=b"\x83\x14\x01" + b"\x00" * 20)
    assert tlv[0] == AUTH_TLV_CRYPTO  # type 133
    assert tlv[1] == 17  # 1 + 16
    assert tlv[2] == 1  # key_id
    assert len(tlv) == 19  # type(1) + len(1) + key_id(1) + hmac(16)
