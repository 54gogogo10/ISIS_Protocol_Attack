"""IS-IS neighbor state machine (ISO 10589)."""
from enum import IntEnum


class ISNeighborState(IntEnum):
    DOWN = 0
    INIT = 1
    UP = 2


class ISNeighbor:
    def __init__(self, sys_id: str, level: int = 1):
        self.sys_id = sys_id
        self.level = level
        self.state = ISNeighborState.DOWN
        self.hold_timer = 0
        self.priority = 0
        self.area_addr = ""
        self.ip_addr = ""
