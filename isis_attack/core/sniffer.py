"""ISIS L2 packet sniffer using pcap-ct + Npcap."""
import threading
import time
from dataclasses import dataclass, field
from typing import List

try:
    import pcap
    HAS_PCAP = True
except (ImportError, OSError):
    HAS_PCAP = False

_MAX_PACKETS = 10000


@dataclass
class LSPEntry:
    lsp_id: str
    sequence: int
    remaining_lifetime: int
    hostname: str = ""


@dataclass
class TopologyModel:
    sys_ids: List[str] = field(default_factory=list)
    area_addrs: List[str] = field(default_factory=list)
    dis_map: dict = field(default_factory=dict)
    lsp_entries: List[LSPEntry] = field(default_factory=list)

    def add_sys(self, sys_id: str, area_addr: str) -> None:
        if sys_id not in self.sys_ids:
            self.sys_ids.append(sys_id)
        if area_addr not in self.area_addrs:
            self.area_addrs.append(area_addr)

    def add_lsp(self, lsp_id: str, sequence: int, remaining_lifetime: int,
                hostname: str = "") -> None:
        self.lsp_entries.append(LSPEntry(
            lsp_id=lsp_id, sequence=sequence,
            remaining_lifetime=remaining_lifetime, hostname=hostname,
        ))


class Sniffer:
    def __init__(self, iface: str):
        self.iface = iface
        self.available = HAS_PCAP
        self._sniffer = None
        self._stop_event = threading.Event()
        self._packets = []
        self._topology = TopologyModel()

    def start(self, timeout: int = 30) -> None:
        if not self.available:
            return
        self._stop_event.clear()
        self._packets = []

        def _capture():
            sniffer = pcap.pcap(name=self.iface, promisc=True, immediate=True)
            sniffer.setfilter("ether proto 0xFEFE")
            deadline = time.monotonic() + timeout
            try:
                for _ts, pkt in sniffer:
                    if time.monotonic() > deadline or self._stop_event.is_set():
                        break
                    if len(self._packets) < _MAX_PACKETS:
                        self._packets.append(pkt)
            except Exception:
                pass

        t = threading.Thread(target=_capture, daemon=True)
        t.start()
        self._sniffer = t

    def stop(self):
        self._stop_event.set()
        return self._packets

    @property
    def packets(self):
        return self._packets

    @property
    def topology(self):
        return self._topology
