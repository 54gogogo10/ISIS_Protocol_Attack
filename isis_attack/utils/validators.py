import re


def is_valid_sys_id(sys_id: str) -> bool:
    clean = sys_id.replace(".", "")
    return len(clean) == 12 and all(c in "0123456789ABCDEFabcdef" for c in clean)


def is_valid_area_addr(area_addr: str) -> bool:
    clean = area_addr.replace(".", "")
    return len(clean) >= 2 and len(clean) % 2 == 0 and all(c in "0123456789ABCDEFabcdef" for c in clean)


def is_valid_mac(mac: str) -> bool:
    pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    return bool(re.match(pattern, mac))


def sys_id_to_hex(sys_id: str) -> str:
    return sys_id.replace(".", "").upper()
