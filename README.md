# phantom-scan

> **Nyoul Labs** — Offensive Security Research & Development

Adaptive timing-based stealth network scanner.

## Overview

Phantom-scan is an adaptive timing-based stealth network scanner designed to
operate below the detection threshold of modern IDS/IPS, NDR, and firewall
logging systems. Developed at **Nyoul Labs** — a specialized offensive security
research lab focused on advanced network exploitation and security tooling.

## Status

**Alpha** — Initial development phase. Core scanning engine, adaptive timing,
and passive reconnaissance are functional.

## What's Included

- [x] Adaptive timing engine with feedback loop
- [x] Stealth TCP SYN scanner with RST termination
- [x] Passive reconnaissance module (ARP, DNS, TCP)
- [x] Configuration management and validation
- [x] JSON report generation
- [x] CLI with Click framework
- [x] Unit tests
- [x] CI/CD pipeline (GitHub Actions)
- [x] Documentation
- [x] Plugin system with community signatures
- [x] Network graph analysis and proxy chain builder
- [x] Multi-hop tunnel management

## Roadmap

### Phase 2: Service Fingerprinting
- Deep packet analysis for service identification
- Custom fingerprint database
- Behavioral service detection

### Phase 3: Exploit Modules
- Automated vulnerability checks against open ports
- Exploit database integration
- Safe exploit delivery framework

### Phase 4: Pivot Engine
- Automatic proxy chain construction
- Multi-hop tunnel management
- Route optimization

### Phase 5: Plugin System
- Third-party module support
- Plugin marketplace
- Community signature library

## Installation

```bash
pip install phantom-scan
```

## Usage

```bash
# Basic scan
phantom-scan -t 192.168.1.1

# Full stealth scan
phantom-scan -t 192.168.1.0/24 -p 1-65535 --min-rtt 5 --max-jitter 30

# Passive reconnaissance
phantom-scan -t 192.168.1.1 --passive
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## License

MIT License — see [LICENSE](LICENSE) for full text.
