"""Tests for utility validators."""
import pytest
from isis_attack.utils.validators import (
    is_valid_sys_id,
    is_valid_area_addr,
    is_valid_mac,
    sys_id_to_hex,
)


class TestSysIdValidator:
    def test_valid_sys_id(self):
        assert is_valid_sys_id("1921.6800.1001") is True

    def test_valid_sys_id_hex(self):
        assert is_valid_sys_id("AAAA.BBBB.CCCC") is True

    def test_invalid_sys_id_too_short(self):
        assert is_valid_sys_id("1921.6800.100") is False

    def test_invalid_sys_id_too_long(self):
        assert is_valid_sys_id("1921.6800.10011") is False

    def test_invalid_sys_id_bad_chars(self):
        assert is_valid_sys_id("1921.6800.100G") is False

    def test_invalid_sys_id_empty(self):
        assert is_valid_sys_id("") is False


class TestAreaAddrValidator:
    def test_valid_area_addr(self):
        assert is_valid_area_addr("49.0001") is True

    def test_valid_area_addr_long(self):
        assert is_valid_area_addr("49.0001.0002") is True

    def test_invalid_area_addr_odd_length(self):
        assert is_valid_area_addr("49.000") is False

    def test_invalid_area_addr_bad_chars(self):
        assert is_valid_area_addr("49.000G") is False

    def test_invalid_area_addr_too_short(self):
        assert is_valid_area_addr("4") is False

    def test_invalid_area_addr_empty(self):
        assert is_valid_area_addr("") is False


class TestMacValidator:
    def test_valid_mac_colon(self):
        assert is_valid_mac("01:80:C2:00:00:14") is True

    def test_valid_mac_dash(self):
        assert is_valid_mac("01-80-C2-00-00-14") is True

    def test_valid_mac_lowercase(self):
        assert is_valid_mac("aa:bb:cc:dd:ee:ff") is True

    def test_invalid_mac_wrong_separator(self):
        assert is_valid_mac("01.80.C2.00.00.14") is False

    def test_invalid_mac_too_short(self):
        assert is_valid_mac("01:80:C2:00:00") is False

    def test_invalid_mac_bad_chars(self):
        assert is_valid_mac("xx:xx:xx:xx:xx:xx") is False

    def test_invalid_mac_empty(self):
        assert is_valid_mac("") is False


class TestSysIdToHex:
    def test_basic(self):
        assert sys_id_to_hex("1921.6800.1001") == "192168001001"

    def test_lowercase(self):
        assert sys_id_to_hex("aaaa.bbbb.cccc") == "AAAABBBBCCCC"

    def test_no_dots(self):
        assert sys_id_to_hex("192168001001") == "192168001001"
