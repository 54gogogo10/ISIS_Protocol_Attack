# ISIS Protocol Attack Simulator

A comprehensive IS-IS (Intermediate System to Intermediate System) protocol attack simulation framework for security research, education, and penetration testing. Supports 13 attack types across 4 categories with both CLI and GUI interfaces.

## Features

- **13 Attack Types** -- Adjacency attacks, LSP attacks, DoS attacks, and protocol-level attacks
- **L2 Transport** -- Raw L2 packet injection and sniffing via Npcap
- **TLV Encoding** -- Full IS-IS TLV encoding/decoding support (TLV 1-22, 128-134)
- **IS-IS Authentication** -- Supports plaintext (TLV 10) and HMAC-MD5 (TLV 133) authentication modes
- **ARP Spoof Engine** -- MITM positioning via ARP cache poisoning
- **Passive & Active Modes** -- Passive sniffing (hub) or active ARP spoof positioning
- **GUI Interface** -- Tkinter-based control panel for attack selection and configuration
- **CLI Interface** -- Click-based command-line interface with all 13 attacks
- **YAML Configuration** -- Support for configuration files with CLI override

## Quick Start

```bash
# Install from source
pip install .

# CLI usage
isis-attack --help
isis-attack iih-inject --iface eth0 --target 01:80:C2:00:00:14

# Launch GUI
python -m isis_attack
```

## Attack Types

| Category | Attack Name | Description |
|----------|-------------|-------------|
| **Adjacency** | `iih-inject` | Inject forged IIH (IS-IS Hello) packets to establish unauthorized adjacencies |
| **Adjacency** | `adjacency-break` | Send crafted IIH packets with mismatched parameters to break existing adjacencies |
| **Adjacency** | `dis-hijack` | Manipulate DIS election by forging IIH packets with high priority |
| **LSP** | `route-inject` | Inject fake LSPs with crafted route information |
| **LSP** | `max-seq` | Send LSPs with maximum sequence number to suppress legitimate updates |
| **LSP** | `purge-lsp` | Send purge LSPs (zero remaining lifetime) to remove LSPs from the LSDB |
| **LSP** | `fight-back` | Simulate LSP fight-back behavior during route poisoning |
| **LSP** | `overload-bit` | Set the overload bit in LSPs to trigger traffic blackholing |
| **DoS** | `flood` | Flood the network with a high rate of IS-IS packets |
| **DoS** | `spf-recalc` | Trigger repeated SPF calculations by rapidly changing LSP content |
| **DoS** | `db-overflow` | Exhaust the IS-IS LSDB by injecting many LSPs |
| **Protocol** | `mitm` | Man-in-the-middle attack between two IS-IS routers |
| **Protocol** | `replay` | Capture and replay IS-IS packets |

## IS-IS Authentication Support

The simulator supports two IS-IS authentication modes:

- **Plaintext (TLV 10)** -- Cleartext password authentication for Hello, CSNP, and PSNP PDUs
- **HMAC-MD5 (TLV 133)** -- Cryptographic authentication per RFC 5304

Authentication can be configured per attack via CLI flags or YAML config.

## Configuration

Attacks can be configured via:
- **CLI parameters** -- Direct command-line flags (see `isis-attack <attack> --help`)
- **YAML config file** -- Reusable configuration files (using `--config` parameter)

### Common configuration parameters

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--iface` | (required) | Network interface for packet injection |
| `--target` | (required) | Target MAC address |
| `--sys-id` | `1921.6800.1001` | IS-IS System ID |
| `--area-addr` | `49.0001` | Area address |
| `--level` | `1` | IS-IS level (1 or 2) |
| `--sniff-duration` | `30` | Sniffing duration in seconds |
| `--packet-rate` | `10` | Packet injection rate (packets/sec) |
| `--max-packets` | `0` | Maximum packets to send (0 = unlimited) |
| `--mode` | `passive` | Operating mode: passive or active |

## Build

```powershell
# Build standalone executable (requires Npcap installer in assets/)
.\build.ps1
```

## Tech Stack

- **Python 3.10+**
- **Scapy** -- Packet manipulation library
- **Click** -- CLI framework
- **PyYAML** -- Configuration parsing
- **pcap-ct** -- PCAP capture backend
- **Tkinter** -- GUI toolkit (stdlib)
- **pytest** -- Testing framework

## Requirements

- Npcap (Windows) / AF_PACKET (Linux) for raw L2 packet injection
- Docker Desktop + FRRouting for integration tests
- Administrative/root privileges for L2 operations

## Testing

```bash
# Unit tests (79 tests)
pytest tests/unit/ -v

# Integration tests — requires Docker Desktop + FRRouting
docker compose -f docker/topo1-single-area/docker-compose.yml up -d
pytest tests/integration/ -v    # 17 tests
docker compose -f docker/topo1-single-area/docker-compose.yml down -v

# Full suite: 96 tests
pytest tests/unit/ tests/integration/ -v
```

Integration tests run against real FRR routers in Docker with ISIS Level-1 broadcast LAN. Each attack verifies packet delivery and post-attack neighbor stability.

## Architecture

```
isis_attack/
  __init__.py          # Package init, version
  __main__.py          # GUI entry (python -m isis_attack)
  core/
    auth.py            # IS-IS auth (plain TLV 10, HMAC-MD5 TLV 133)
    packet.py          # PDU construction (IIH/LSP + TLV builders + checksum)
    neighbor.py        # IS neighbor state machine (Down/Init/Up)
    sniffer.py         # L2 sniffer (pcap-ct, thread-safe)
    arp_spoof.py       # ARP spoof engine (MAC discovery + restore)
    active_engine.py   # Active adjacency engine (sniff→adjacency→LSP inject)
  attacks/
    base.py            # BaseAttack (setup/launch/verify/teardown lifecycle)
    adjacency/         # iih-inject, adjacency-break, dis-hijack
    lsp/               # route-inject, max-seq, purge-lsp, fight-back, overload-bit
    dos/               # flood, spf-recalc, db-overflow
    protocol/          # mitm, replay
  config/
    config.py          # Config loader (default→YAML→CLI 3-layer merge)
    types.py           # 6 dataclass config types
  network/
    adapter.py         # L2 NIC adapter (MAC/IP)
    sender.py          # PacketSender (Scapy sendp, rate-limited)
  cli/
    main.py            # Click CLI entry
    commands.py        # 13 attack subcommands
    formatters.py      # Output formatters (table/json)
  gui/
    app.py             # Main window (1100×720)
    attack_tree.py     # 4-category attack tree
    config_form.py     # Dynamic config form
    log_panel.py       # Thread-safe log
    runner.py          # Background attack thread
    pcap_tools.py      # PCAP import
    styles.py          # Color/font constants
  utils/
    validators.py      # SysID/AreaAddr/MAC validators
tests/
  unit/                # 79 unit tests
  integration/         # 17 Docker FRR integration tests
docker/
  topo1-single-area/   # 2 FRR routers + attacker container
```

## License

MIT
