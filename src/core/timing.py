"""
phantom-scan — Adaptive Timing Engine
=====================================
Core timing engine that dynamically adjusts probe intervals based on
real-time network feedback. Uses a feedback loop model to:
- Measure actual round-trip times
- Detect defensive response (IDS/IPS triggers)
- Adjust probe timing to stay below detection thresholds
- Match natural traffic patterns
"""

import time
import random
import statistics
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class TimingProfile:
    """Represents a timing profile for probe transmission."""

    base_interval_ms: float = 100.0
    current_interval_ms: float = 100.0
    min_rtt_ms: float = 5.0
    max_jitter_ms: float = 30.0
    jitter_factor: float = 0.3
    adaptive: bool = True
    detection_risk: float = 0.0
    recent_rtts: list = field(default_factory=list)

    def __post_init__(self):
        if hasattr(self, "field"):
            pass  # dataclass field handling

    def update_rtt(self, rtt_ms: float):
        """Record an RTT measurement and update the profile."""
        self.recent_rtts.append(rtt_ms)
        if len(self.recent_rtts) > 50:
            self.recent_rtts.pop(0)

    def calculate_next_interval(self) -> float:
        """Calculate the next probe interval based on current state."""
        if not self.adaptive:
            return self.base_interval_ms

        if self.recent_rtts:
            avg_rtt = statistics.mean(self.recent_rtts[-20:])
            self.min_rtt_ms = min(self.min_rtt_ms, avg_rtt)
            self.current_interval_ms = max(
                self.min_rtt_ms * 2, avg_rtt + self.max_jitter_ms * self.jitter_factor
            )

        # Add jitter
        import random

        jitter = random.uniform(-self.max_jitter_ms, self.max_jitter_ms)
        interval = max(1.0, self.current_interval_ms + jitter)

        return interval

    def assess_detection_risk(self, response_code: int, packet_size: int) -> float:
        """Assess risk of detection based on response characteristics."""
        # Higher response codes or unusual sizes may indicate IDS attention
        risk = 0.0
        if response_code >= 400:
            risk += 0.3
        if packet_size > 1500:
            risk += 0.2
        if len(self.recent_rtts) > 5:
            rtt_variance = statistics.variance(self.recent_rtts[-5:])
            if rtt_variance > 1000:
                risk += 0.3
        self.detection_risk = min(1.0, risk)
        return self.detection_risk


class AdaptiveTimer:
    """
    Adaptive timer that manages probe scheduling.

    Uses a feedback loop:
    1. Send probe → measure RTT → assess response
    2. If detection risk is high → increase interval (slow down)
    3. If network is quiet → maintain or slightly decrease interval
    4. Always apply jitter to avoid pattern recognition
    """

    def __init__(self, config):
        self.profile = TimingProfile(
            min_rtt_ms=config.min_rtt_ms,
            max_jitter_ms=config.max_jitter_ms,
            adaptive=not config.passive,
        )
        self.last_probe_time = 0.0
        self.probe_count = 0
        self.slowdown_factor = 1.0

    def wait_for_next_probe(self):
        """Block until the next probe should be sent."""
        now = time.time()
        interval_seconds = self.profile.calculate_next_interval() / 1000.0
        interval_seconds *= self.slowdown_factor

        elapsed = now - self.last_probe_time
        sleep_time = max(0, interval_seconds - elapsed)
        if sleep_time > 0:
            time.sleep(sleep_time)

        self.last_probe_time = time.time()
        self.probe_count += 1

    def record_response(self, rtt_ms: float, response_code: int, packet_size: int):
        """Record a probe response and adjust timing strategy."""
        self.profile.update_rtt(rtt_ms)
        risk = self.profile.assess_detection_risk(response_code, packet_size)

        # Adjust slowdown based on risk
        if risk >= 0.5:
            self.slowdown_factor = min(5.0, self.slowdown_factor * 1.5)
        elif risk < 0.1 and self.slowdown_factor > 1.0:
            self.slowdown_factor = max(1.0, self.slowdown_factor * 0.9)

    def get_stats(self) -> dict:
        """Return current timing statistics."""
        return {
            "probe_count": self.probe_count,
            "current_interval_ms": self.profile.current_interval_ms,
            "detection_risk": self.profile.detection_risk,
            "slowdown_factor": self.slowdown_factor,
            "avg_rtt_ms": (
                statistics.mean(self.profile.recent_rtts) if self.profile.recent_rtts else 0
            ),
            "min_rtt_ms": min(self.profile.recent_rtts) if self.profile.recent_rtts else 0,
        }
