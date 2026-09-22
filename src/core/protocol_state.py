"""
phantom-scan — Protocol State Analyzer
=========================================
Analyzes protocol state machines to determine service behavior
and detect protocol-level anomalies.

This module performs stateful protocol analysis without sending
additional probes — it observes existing traffic patterns to
determine service behavior and detect anomalies.
"""

import logging
from typing import Optional, Dict, List
from dataclasses import dataclass, field
from collections import defaultdict

from scapy.all import TCP, IP

logger = logging.getLogger("phantom-scan")


@dataclass
class ProtocolState:
    """Tracks the state of a protocol connection."""

    port: int
    state: str = "CLOSED"
    packets_seen: int = 0
    syn_count: int = 0
    syn_ack_count: int = 0
    rst_count: int = 0
    fin_count: int = 0
    data_transferred: int = 0
    anomalies: List[str] = field(default_factory=list)

    def transition(self, packet) -> str:
        """
        Update state based on observed packet.
        Returns the new state string.
        """
        self.packets_seen += 1

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = tcp.flags

            if flags & 0x02 and not (flags & 0x10):  # SYN only (not SYN-ACK)
                self.syn_count += 1
                if self.state == "CLOSED":
                    self.state = "SYN_SENT"

            elif flags == 0x12:  # SYN-ACK (exact match: SYN + ACK)
                self.syn_ack_count += 1
                if self.state == "SYN_SENT":
                    self.state = "SYN_ACK_RECEIVED"

            if flags & 0x04:  # RST
                self.rst_count += 1
                self.state = "RESET"

            if flags & 0x01:  # FIN
                self.fin_count += 1
                if self.state == "ESTABLISHED":
                    self.state = "CLOSE_WAIT"

            # Check for data
            if hasattr(tcp, "payload") and len(tcp.payload) > 0:
                self.data_transferred += len(tcp.payload)
                if self.state == "SYN_ACK_RECEIVED":
                    self.state = "ESTABLISHED"

            # Anomaly detection
            self._detect_anomalies(tcp)

        return self.state

    def _detect_anomalies(self, tcp):
        """Detect protocol-level anomalies."""
        flags = tcp.flags

        # Check for simultaneous open (SYN + FIN)
        if flags & 0x02 and flags & 0x01:
            self.anomalies.append("Simultaneous_open_detected")

        # Check for SYN flooding indicators
        if self.syn_count > 20 and self.syn_ack_count < self.syn_count * 0.5:
            self.anomalies.append("Possible_SYN_flood")

        # Check for port scanning patterns (rapid SYN without completion)
        if self.syn_count > 10 and self.syn_ack_count == 0:
            self.anomalies.append("SYN_scan_pattern")

        # Check for RST storm
        if self.rst_count > 50:
            self.anomalies.append("RST_storm")

        # Check for unusual flag combinations
        if flags & 0x08:  # PSH flag on initial probe
            self.anomalies.append("PSH_on_initial_probe")

        # Check for window size of 0 (connection closing)
        if tcp.window == 0:
            self.anomalies.append("Zero_window_size")


class ProtocolStateAnalyzer:
    """
    Main protocol state analyzer.

    Maintains state machines for all observed connections and
    provides protocol-level intelligence.
    """

    def __init__(self):
        self.states: Dict[int, ProtocolState] = {}
        self.connection_history: List[Dict] = []
        self.anomaly_count = 0
        self._lock = None  # For thread safety in future

    def observe_packet(self, packet):
        """
        Process a packet and update protocol state machines.

        Args:
            packet: Scapy packet object
        """
        if not packet.haslayer(TCP):
            return

        tcp = packet[TCP]
        dport = tcp.dport
        sport = tcp.sport

        # Track destination port state
        if dport not in self.states:
            self.states[dport] = ProtocolState(port=dport)

        state = self.states[dport].transition(packet)

        # Track source port state (for response analysis)
        if sport not in self.states:
            self.states[sport] = ProtocolState(port=sport)

        # Store connection history entry
        entry = {
            "sport": sport,
            "dport": dport,
            "state": state,
            "flags": str(tcp.flags),
            "window": tcp.window,
            "seq": tcp.seq,
            "ack": tcp.ack,
            "packet_size": len(packet),
        }
        self.connection_history.append(entry)

    def get_service_state(self, port: int) -> Optional[str]:
        """Get the current state of a service on a specific port."""
        if port in self.states:
            return self.states[port].state
        return None

    def get_anomalies(self) -> List[Dict]:
        """Return all detected protocol anomalies."""
        anomalies = []
        for port, state in self.states.items():
            if state.anomalies:
                for anomaly in state.anomalies:
                    anomalies.append(
                        {
                            "port": port,
                            "anomaly": anomaly,
                            "state": state.state,
                        }
                    )
        return anomalies

    def get_protocol_report(self) -> dict:
        """Generate a comprehensive protocol analysis report."""
        report = {
            "total_connections": len(self.connection_history),
            "observed_ports": list(self.states.keys()),
            "anomaly_count": len(self.get_anomalies()),
            "port_states": {},
        }

        for port, state in self.states.items():
            report["port_states"][port] = {
                "state": state.state,
                "packets_seen": state.packets_seen,
                "data_transferred": state.data_transferred,
                "anomalies": state.anomalies,
            }

        return report
