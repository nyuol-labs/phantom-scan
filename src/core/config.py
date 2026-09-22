"""
phantom-scan — Configuration Module
===================================
Central configuration management for all scan parameters.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Config:
    """All configuration for a phantom-scan session."""

    target: str = "127.0.0.1"
    port_range: str = "1-1024"
    passive: bool = False
    min_rtt_ms: int = 5
    max_jitter_ms: int = 30
    interface: Optional[str] = None
    verbose: int = 0
    output: Optional[str] = None

    # Derived attributes
    @property
    def parsed_ports(self) -> tuple:
        """Parse port range string into (start, end) tuple."""
        parts = self.port_range.split("-")
        if len(parts) == 2:
            return (int(parts[0]), int(parts[1]))
        return (int(parts[0]), int(parts[0]))

    def to_dict(self) -> dict:
        """Serialize config to dictionary."""
        return {
            "target": self.target,
            "port_range": self.port_range,
            "passive": self.passive,
            "min_rtt_ms": self.min_rtt_ms,
            "max_jitter_ms": self.max_jitter_ms,
            "interface": self.interface,
            "verbose": self.verbose,
            "output": self.output,
        }

    def validate(self) -> bool:
        """Validate configuration parameters."""
        errors = []
        if self.min_rtt_ms < 1:
            errors.append("min_rtt_ms must be >= 1")
        if self.max_jitter_ms < 0:
            errors.append("max_jitter_ms must be >= 0")
        if self.max_jitter_ms >= self.min_rtt_ms * 10:
            errors.append("max_jitter_ms should be less than min_rtt_ms * 10")
        if errors:
            raise ValueError(f"Configuration errors: {'; '.join(errors)}")
        return True
