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

## Architecture

```
isis_attack/
  __init__.py          # Package init, version
  __main__.py          # GUI entry point (python -m isis_attack)
  config/
    config.py          # Configuration loader (YAML + CLI merge)
    types.py           # Dataclass types for all configs
    validators.py      # Input validation
  core/
    auth.py            # IS-IS authentication (plaintext, HMAC-MD5)
    packet.py          # PDU construction (IIH, LSP, SNP)
    neighbor.py        # Neighbor state machine
    sniffer.py         # L2 sniffer
    arp_spoof.py       # ARP spoof engine
    active_engine.py   # Active attack engine
  network/
    adapter.py         # L2 network adapter
    sender.py          # Packet sender
  attacks/
    base.py            # BaseAttack abstract class
    adjacency/         # IIH injection, adjacency break, DIS hijack
    lsp/               # Route injection, max-seq, purge, fight-back, overload-bit
    dos/               # Flood, SPF recalc, DB overflow
    protocol/          # MITM, replay
  gui/
    app.py             # Main GUI window
    attack_tree.py     # Attack tree navigation
    config_form.py     # Configuration form
    log_panel.py       # Log display panel
    runner.py          # Background attack thread runner
    pcap_tools.py      # PCAP file import
    styles.py          # Color scheme and fonts
  cli/
    main.py            # Click CLI entry point
    commands.py        # Attack command registration
    formatters.py      # Output formatters (table, json)
  utils/
    log.py             # Logging utilities
    validators.py      # Validation helpers
tests/
  unit/                # Unit tests for all components
  integration/         # Integration tests
```

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

- Npcap (Windows) for raw packet injection
- Administrative/root privileges for L2 operations

## License

MIT
