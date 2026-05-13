"""ISIS authentication (TLV type 10/133).

Supports: none, plain (TLV 10), HMAC-MD5 (TLV 133).
"""
import hashlib
import hmac
import struct

AUTH_NONE = 0
AUTH_PLAIN = 1
AUTH_MD5 = 2

AUTH_TLV_PLAIN = 10
AUTH_TLV_CRYPTO = 133


def build_auth_tlv(auth_type: int, auth_key: bytes,
                   pdu_bytes: bytes = b"", crypto_seq: int = 0) -> bytes:
    """Build an ISIS authentication TLV.

    Args:
        auth_type: 0 (none), 1 (plain TLV 10), 2 (HMAC-MD5 TLV 133)
        auth_key: Key/password bytes
        pdu_bytes: Full ISIS PDU bytes (needed for HMAC-MD5 to zero out TLV)
        crypto_seq: Cryptographic sequence number (HMAC-MD5 only)

    Returns:
        TLV bytes (type + length + value) or empty bytes for none
    """
    if auth_type == AUTH_NONE:
        return b""

    if auth_type == AUTH_PLAIN:
        return struct.pack("!BB", AUTH_TLV_PLAIN, len(auth_key)) + auth_key

    if auth_type == AUTH_MD5:
        # Build the TLV skeleton with key_id
        tlv = struct.pack("!BBB", AUTH_TLV_CRYPTO, 17, 1)
        data = pdu_bytes + tlv + b"\x00" * 16
        digest = hmac.HMAC(auth_key, data, hashlib.md5).digest()
        return tlv + digest

    raise ValueError(f"Unsupported auth_type: {auth_type}")


_AUTH_NAMES = {AUTH_NONE: "none", AUTH_PLAIN: "plain", AUTH_MD5: "md5"}


def auth_type_name(t: int) -> str:
    return _AUTH_NAMES.get(t, f"unknown({t})")
