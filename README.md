# ISIS 协议攻击模拟器

IS-IS（中间系统到中间系统）协议攻击模拟与安全研究工具。基于 Python，支持 CLI + GUI 双界面，覆盖 4 大类 13 种攻击方式。

> **免责声明**：本工具仅供安全研究、教育用途和授权渗透测试使用。使用者应确保在**合法授权**的网络环境中运行，并遵守所在国家/地区的法律法规。作者不对任何未经授权的使用、滥用或由此产生的后果承担责任。**请勿在未授权的网络或生产环境中使用本工具。**

## 特性

- **13 种攻击类型** — 覆盖邻接关系、LSP、DoS、协议级操控 4 大类
- **L2 传输** — 基于 Npcap/AF_PACKET 的原始 L2 报文注入与嗅探
- **TLV 编码** — 完整的 IS-IS TLV 编解码（类型 1-22, 128-137）
- **IS-IS 认证** — 支持明文（TLV 10）和 HMAC-MD5（TLV 133）认证
- **ARP 欺骗引擎** — 通过 ARP 缓存投毒实现中间人定位
- **双嗅探模式** — 集线器环境混杂嗅探 / 交换环境 ARP 欺骗
- **GUI 操作面板** — 基于 Tkinter 的可视化攻击选择与配置界面
- **CLI 命令行** — 基于 Click 的 13 子命令命令行接口
- **YAML 配置** — 支持配置文件 + CLI 参数覆盖

## 快速开始

```bash
# 从源码安装
pip install .

# 命令行使用
isis-attack --help
isis-attack iih-inject --iface eth0 --target 01:80:C2:00:00:14

# 启动 GUI
python -m isis_attack
```

## 攻击类型

| 类别 | 攻击名称 | 描述 | 攻击手法 |
|------|---------|------|---------|
| **邻接关系** | `iih-inject` | IIH 注入攻击 | 发送伪造 IIH 建立未授权 IS-IS 邻接关系 |
| **邻接关系** | `adjacency-break` | 邻接破坏攻击 | 发送畸形 IIH（错误 Area + Hold=0）破坏合法邻接 |
| **邻接关系** | `dis-hijack` | DIS 抢占攻击 | 发送 Priority=127 的 IIH 抢占 DIS 角色 |
| **LSP** | `route-inject` | 路由注入攻击 | 注入含毒化 IP Reachability TLV 的 LSP 篡改路由表 |
| **LSP** | `max-seq` | 最大序列号攻击 | 发送 Sequence=0xFFFFFFFF 的 LSP 覆盖合法 LSP |
| **LSP** | `purge-lsp` | LSP 清除攻击 | 发送 Remaining Lifetime=0 的 LSP 迫使目标清除 LSP |
| **LSP** | `fight-back` | 对抗攻击 | 持续注入递增序列号的对抗 LSP，阻止合法 LSP 传播 |
| **LSP** | `overload-bit` | 过载位攻击 | 设置 LSP overload-bit 使目标路由器被排除在 SPF 之外 |
| **DoS** | `flood` | 泛洪攻击 | 多线程高频发送 IIH/LSP 报文耗尽路由器 CPU |
| **DoS** | `spf-recalc` | SPF 重计算攻击 | 持续注入变化的 LSP 迫使路由器反复执行 SPF 计算 |
| **DoS** | `db-overflow` | 数据库溢出攻击 | 注入大量 LSP 填满链路状态数据库 |
| **协议操控** | `mitm` | 中间人攻击 | 拦截 ISIS PDU → 篡改 → 转发（支持 drop/modify/forward） |
| **协议操控** | `replay` | 重放攻击 | 从 pcap 文件读取 ISIS 报文重新发送，引发路由震荡 |

## 配置参数

攻击可通过以下方式配置（优先级：默认值 → YAML → CLI）：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--iface` | (必填) | 网络接口名称 |
| `--target` | (必填) | 目标 MAC 地址 |
| `--sys-id` | `1921.6800.1001` | IS-IS 系统 ID |
| `--area-addr` | `49.0001` | 区域地址 |
| `--level` | `1` | IS-IS 级别（1 或 2） |
| `--sniff-duration` | `30` | 嗅探持续时间（秒） |
| `--packet-rate` | `10` | 发包速率（包/秒） |
| `--max-packets` | `0` | 最大发包数（0=无限制） |
| `--mode` | `passive` | 攻击模式：passive 或 active |
| `--sniff-mode` | `hub` | 嗅探模式：hub 或 arp_spoof |

## 测试

```bash
# 单元测试 (79 项)
pytest tests/unit/ -v

# 集成测试 — 需要 Docker Desktop + FRRouting
docker compose -f docker/topo1-single-area/docker-compose.yml up -d
pytest tests/integration/ -v    # 17 tests
docker compose -f docker/topo1-single-area/docker-compose.yml down -v

# 全部测试 (96 项)
pytest tests/unit/ tests/integration/ -v
```

集成测试通过 Docker FRR 容器构建真实 ISIS 拓扑（L1 广播 LAN，2 台路由器 + 1 台攻击机），验证每种攻击的报文投递和攻击后邻居状态稳定性。

## 架构

```
isis_attack/
  __init__.py          # 包初始化、版本号
  __main__.py          # GUI 入口 (python -m isis_attack)
  core/
    auth.py            # IS-IS 认证 (明文 TLV 10 / HMAC-MD5 TLV 133)
    packet.py          # PDU 构造 (IIH/LSP + TLV 构建 + 校验和)
    neighbor.py        # IS 邻居状态机 (Down/Init/Up)
    sniffer.py         # L2 嗅探器 (pcap-ct, 线程安全)
    arp_spoof.py       # ARP 欺骗引擎 (MAC 学习 + 恢复)
    active_engine.py   # 主动模式引擎 (嗅探→邻接→LSP 注入)
  attacks/
    base.py            # BaseAttack 抽象基类 (setup/launch/verify/teardown)
    adjacency/         # iih-inject, adjacency-break, dis-hijack
    lsp/               # route-inject, max-seq, purge-lsp, fight-back, overload-bit
    dos/               # flood, spf-recalc, db-overflow
    protocol/          # mitm, replay
  config/
    config.py          # 配置加载器 (默认→YAML→CLI 三层合并)
    types.py           # 6 个 dataclass 配置类型
  network/
    adapter.py         # L2 网卡抽象 (MAC/IP)
    sender.py          # PacketSender (Scapy sendp, 速率限制)
  cli/
    main.py            # Click CLI 入口
    commands.py        # 13 攻击子命令注册
    formatters.py      # 输出格式化 (table/json)
  gui/
    app.py             # 主窗口 (1100×720)
    attack_tree.py     # 4 类攻击树
    config_form.py     # 动态配置表单
    log_panel.py       # 线程安全日志面板
    runner.py          # 后台攻击线程
    pcap_tools.py      # PCAP 文件导入
    styles.py          # 颜色/字体常量
  utils/
    validators.py      # SysID/AreaAddr/MAC 校验
tests/
  unit/                # 79 项单元测试
  integration/         # 17 项 Docker FRR 集成测试
docker/
  topo1-single-area/   # 2 FRR 路由器 + 1 攻击机
```

## 技术栈

| 组件 | 技术 |
|------|------|
| 语言 | Python 3.10+ |
| 协议引擎 | Scapy + 手动字节级 TLV 构建 |
| 认证 | hashlib + hmac（纯标准库） |
| 报文捕获 | pcap-ct + Npcap (Windows) / AF_PACKET (Linux) |
| CLI | Click（13 子命令） |
| GUI | Tkinter + ttk |
| 打包 | PyInstaller `--onefile` |
| 测试 | pytest（96 tests: 79 unit + 17 integration） |
| 配置 | YAML（默认→YAML→CLI 三层优先级） |
| 集成拓扑 | Docker + FRRouting |

## 依赖

- Npcap (Windows) / AF_PACKET (Linux) — L2 原始包注入
- Docker Desktop + FRRouting — 集成测试环境
- 管理员/root 权限 — L2 操作

## 构建

```powershell
# 构建独立可执行文件（需先将 Npcap 安装程序放入 assets/）
.\build.ps1
```

## 许可证

MIT
