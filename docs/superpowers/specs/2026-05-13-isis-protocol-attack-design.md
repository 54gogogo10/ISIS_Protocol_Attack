# ISIS Protocol Attack Simulator — Design Spec

## Overview

ISIS (Intermediate System to Intermediate System) 协议攻击模拟工具，Python 库 + GUI + CLI 三层架构，与 OSPF_Protocol_Attack 项目架构对称，覆盖 13 种 ISIS 攻击。

## Architecture

```
isis_attack/
├── core/           # 核心引擎
│   ├── auth.py         # ISIS 认证 (TLV type 10/133, 明文/HMAC-MD5/Crypto)
│   ├── packet.py       # ISIS PDU 构造/解析 (IIH/LSP/CSNP/PSNP + TLV 字节级构建)
│   ├── neighbor.py     # 邻居状态机 (Down/Init/Up + DIS 选举)
│   ├── sniffer.py      # L2 被动嗅探 (pcap-ct + Npcap)
│   ├── arp_spoof.py    # ARP 欺骗引擎 (复用 OSPF 项目)
│   └── active_engine.py # 主动模式引擎 (嗅探→邻接→LSP注入)
├── attacks/        # 攻击插件
│   ├── base.py         # BaseAttack 抽象基类 (4 阶段)
│   ├── adjacency/      # iih-inject, adjacency-break, dis-hijack
│   ├── lsp/            # route-inject, max-seq, purge-lsp, fight-back, overload-bit
│   ├── dos/            # flood, spf-recalc, db-overflow
│   └── protocol/       # mitm, replay
├── network/        # 网络层
│   ├── adapter.py      # 网卡抽象 (L2 接口, MAC 获取)
│   └── sender.py       # 发包器 (Scapy sendp, L2 发送)
├── config/         # 配置体系
│   ├── config.py       # YAML+CLI 三层合并
│   └── types.py        # 6 个 dataclass
├── cli/            # Click CLI (13 子命令)
├── gui/            # Tkinter GUI
├── utils/          # 工具函数
tests/
├── unit/
└── integration/    # Docker FRR
```

## ISIS Transport

- L2 协议，直接封装在 Ethernet 帧中 (DSAP/SSAP = 0xFEFE)
- L1 组播 MAC: 01:80:C2:00:00:14 (AllL1ISs)
- L2 组播 MAC: 01:80:C2:00:00:15 (AllL2ISs)
- Scapy `sendp()` (L2) 而非 OSPF 的 `send()` (L3)
- 不支持 IP 封装 — 无 IP 头

## ISIS PDU Types

| PDU Type | Value | Description |
|----------|-------|-------------|
| L1 IIH | 15 | L1 IS-IS Hello |
| L2 IIH | 16 | L2 IS-IS Hello |
| P2P IIH | 17 | Point-to-Point Hello |
| L1 LSP | 18 | L1 Link State PDU |
| L2 LSP | 20 | L2 Link State PDU |
| L1 CSNP | 24 | L1 Complete SNP |
| L2 CSNP | 25 | L2 Complete SNP |
| L1 PSNP | 26 | L1 Partial SNP |
| L2 PSNP | 27 | L2 Partial SNP |

## TLV Encoding

All ISIS data uses TLV (Type-Length-Value) encoding. Key TLVs:

- **Area Addresses (1)**: 区域地址列表
- **IS Neighbors (6)**: 邻居 MAC
- **IP Interface Address (132)**: 接口 IP
- **IP Internal Reachability (128)**: 内部路由
- **IP External Reachability (130)**: 外部路由
- **Authentication (10/133)**: 认证信息
- **Protocols Supported (129)**: 支持的协议
- **Hostname (137)**: 动态主机名

## Attack Types

### Adjacency (adjacency/)
1. **iih-inject**: 注入伪造 IIH 建立未授权邻接。预期：虚假邻居关系
2. **adjacency-break**: 畸形 IIH（错误 Area/Hold=0）破坏邻接。预期：合法邻接断开
3. **dis-hijack**: Priority=127 抢占 DIS。预期：成为伪 DIS，控制泛洪

### LSP (lsp/)
4. **route-inject**: 注入毒化 IP Reachability TLV 篡改路由表。预期：路由被篡改
5. **max-seq**: Sequence=0xFFFFFFFF 的 LSP 覆盖合法 LSP。预期：合法 LSP 900s 内不可更新
6. **purge-lsp**: Remaining Lifetime=0 清除 LSP。预期：LSP 被清除
7. **fight-back**: 递增序列号持续对抗。预期：合法 LSP 不断被覆盖
8. **overload-bit**: 设置 OL bit 使路由器被排除在 SPF 外。预期：流量绕行

### DoS (dos/)
9. **flood**: 多线程 IIH/LSP 泛洪。预期：CPU 耗尽
10. **spf-recalc**: 持续变化 LSP 迫使 SPF 重算。预期：CPU 飙升
11. **db-overflow**: 大量 LSP 填满 LSDB。预期：数据库溢出

### Protocol (protocol/)
12. **mitm**: 拦截→篡改 ISIS PDU→转发。预期：路由被操控
13. **replay**: 从 pcap 重放 ISIS 报文。预期：路由震荡

## Config Types

```python
AttackConfig — iface, target, mode, sniff_mode, router_id, area_id, ...
HelloInjectionConfig — hello_interval, hold_timer, priority, auth_*, ...
LSPConfig — lsp_id, sequence, remaining_lifetime, overload_bit, metric, ...
DoSConfig — duration, thread_count, lsp_change_interval, lsp_count
MITMConfig — target_a, target_b, action, modify_rules
ReplayConfig — capture_file, replay_loop, replay_interval
```

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Python 3.10+ |
| Protocol | Scapy (`scapy.contrib.isis`) + manual byte-level TLV construction |
| Auth | hashlib + hmac (stdlib) |
| Capture | pcap-ct + Npcap (Windows) / AF_PACKET (Linux) |
| CLI | Click (13 subcommands) |
| GUI | Tkinter + ttk |
| Packager | PyInstaller --onefile |
| Tests | pytest |
| Config | YAML (default → YAML → CLI) |
| Integration | Docker + FRRouting |
