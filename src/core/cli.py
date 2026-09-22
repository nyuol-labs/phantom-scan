"""
phantom-scan — Adaptive Timing-Based Stealth Network Scanner
=============================================================
Core entry point and CLI handler.
"""

import sys
import os

# Ensure src/ is on the path when running directly
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.config import Config
from src.core.scanner import PhantomScanner
from src.core.timing import AdaptiveTimer
from src.modules.passive import PassiveRecon


def main():
    """Entry point for phantom-scan CLI."""
    import click

    @click.command()
    @click.option("-t", "--target", required=True, help="Target IP or CIDR range")
    @click.option("-p", "--ports", default="1-1024", help="Port range to scan")
    @click.option("--passive", is_flag=True, help="Passive reconnaissance only")
    @click.option("--min-rtt", default=5, type=int, help="Minimum RTT in ms")
    @click.option("--max-jitter", default=30, type=int, help="Maximum jitter in ms")
    @click.option("--interface", "-i", default=None, help="Network interface")
    @click.option("-v", "--verbose", count=True, help="Verbosity level")
    @click.option("--output", "-o", default=None, help="Output file path")
    def cli(target, ports, passive, min_rtt, max_jitter, interface, verbose, output):
        """Phantom-scan: adaptive timing-based stealth network scanner."""
        config = Config(
            target=target,
            port_range=ports,
            passive=passive,
            min_rtt_ms=min_rtt,
            max_jitter_ms=max_jitter,
            interface=interface,
            verbose=verbose,
            output=output,
        )
        scanner = PhantomScanner(config)
        scanner.run()

    cli()


if __name__ == "__main__":
    main()
