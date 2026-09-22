# phantom-scan Documentation

> **Nyoul Labs** — Offensive Security Research & Development

## Overview

Phantom-scan is an adaptive timing-based stealth network scanner
developed at Nyoul Labs.

## Architecture

```
src/
├── core/
│   ├── __init__.py          # Package initialization
│   ├── cli.py               # Command-line interface
│   ├── config.py            # Configuration management
│   ├── scanner.py           # Main scanning orchestration
│   └── timing.py            # Adaptive timing engine
├── modules/
│   ├── __init__.py          # Package initialization
│   └── passive.py           # Passive reconnaissance
└── plugins/                 # Future plugin system
    └── (plug-in modules)
```

## Quick Start

### Install

```bash
pip install phantom-scan
```

### Basic Scan

```bash
# Scan a single host
phantom-scan -t 192.168.1.1

# Scan a subnet
phantom-scan -t 192.168.1.0/24

# Custom port range
phantom-scan -t 192.168.1.1 -p 1-65535

# Passive reconnaissance only
phantom-scan -t 192.168.1.1 --passive

# Save results to file
phantom-scan -t 192.168.1.1 -o results.json
```

### Timing Tuning

```bash
# Aggressive scanning (low RTT, low jitter)
phantom-scan -t 192.168.1.1 --min-rtt 2 --max-jitter 5

# Ultra-stealth (high RTT, high jitter)
phantom-scan -t 192.168.1.1 --min-rtt 100 --max-jitter 200
```

## Adaptive Timing Engine

The timing engine uses a feedback loop:

1. **Send Probe** → Measure RTT
2. **Analyze Response** → Assess detection risk
3. **Adjust Interval** → Increase if risky, maintain if safe
4. **Apply Jitter** → Randomize timing to avoid pattern recognition
5. **Repeat** → Continuously adapt to network conditions

Key parameters:
- **min_rtt_ms**: Minimum round-trip time (aggressiveness baseline)
- **max_jitter_ms**: Maximum randomization (stealth level)
- **slowdown_factor**: Multiplier when detection risk is high
- **detection_risk**: Current risk score (0.0–1.0)

## Modules

### Passive Reconnaissance

Run `--passive` to gather intelligence without generating any probe traffic.
The passive module:
- Sniffs ARP packets to discover hosts
- Monitors DNS queries for domain intelligence
- Tracks TCP traffic patterns for service discovery
- Operates completely invisibly

### Future Modules

- **Service Fingerprinting**: Deep service identification via behavioral analysis
- **Exploit Modules**: Automated vulnerability exploitation
- **Pivot Engine**: Automatic proxy chain construction
- **Exfiltration**: Covert data channels over allowed protocols

## Configuration Reference

| Option | Flag | Default | Description |
|--------|------|---------|-------------|
| Target | `-t` | 127.0.0.1 | Target IP or CIDR |
| Port Range | `-p` | 1-1024 | Port range to scan |
| Passive | `--passive` | False | Passive recon only |
| Min RTT | `--min-rtt` | 5 | Minimum RTT in ms |
| Max Jitter | `--max-jitter` | 30 | Maximum jitter in ms |
| Interface | `-i` | default | Network interface |
| Verbose | `-v` | 0 | Verbosity level |
| Output | `-o` | None | Output file path |

## Testing

```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=src --cov-report=html

# Run specific test class
python -m pytest tests/test_core.py -v
```

## License

MIT — see LICENSE for details.
