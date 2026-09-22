"""
phantom-scan — Service Fingerprinting Module
=================================================
Identifies services running on open ports through behavioral analysis
of TCP response characteristics rather than banner grabbing.

Fingerprinting techniques:
- TCP window size analysis
- TTL and hop count estimation
- MSS and TCP option ordering
- Protocol state machine analysis
- Response timing signatures
- Service-specific behavior patterns

No AI/ML — all fingerprinting is based on deterministic protocol analysis
and pattern matching against known service signatures.
"""

import logging
import re
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass, field

from scapy.all import IP, TCP, sr1, conf

logger = logging.getLogger("phantom-scan")


@dataclass
class ServiceFingerprint:
    """Represents a detected service fingerprint."""

    port: int
    service: str
    version: str = "unknown"
    protocol: str = "tcp"
    confidence: float = 0.0
    fingerprint_data: Dict = field(default_factory=dict)
    os_hint: str = "unknown"
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "service": self.service,
            "version": self.version,
            "protocol": self.protocol,
            "confidence": self.confidence,
            "os_hint": self.os_hint,
            "fingerprint_data": self.fingerprint_data,
            "details": self.details,
        }

    def __repr__(self):
        return f"<ServiceFingerprint port={self.port} service={self.service} confidence={self.confidence:.2f}>"


@dataclass
class ResponseSignature:
    """Captures all observable characteristics from a TCP response."""

    window_size: int = 0
    ttl: int = 0
    mss: int = 0
    sack_perm: bool = False
    timestamp: bool = False
    wscale: int = 0
    options_order: str = ""
    tcp_options: List[str] = field(default_factory=list)
    ip_id: int = 0
    df_flag: bool = False
    mf_flag: bool = False
    protocol: str = ""
    rtt: float = 0.0

    def capture(self, packet) -> "ResponseSignature":
        """Extract all observable characteristics from a packet."""
        if packet.haslayer(IP):
            ip = packet[IP]
            self.ttl = ip.ttl
            self.ip_id = ip.id
            self.df_flag = bool(ip.flags & 0x02)  # Don't Fragment
            self.mf_flag = bool(ip.flags & 0x01)  # More Fragments

        if packet.haslayer(TCP):
            tcp = packet[TCP]
            self.window_size = tcp.window
            self.timestamp = bool(tcp.options and any(o[0] == "Timestamp" for o in tcp.options))
            self.sack_perm = bool(tcp.options and any(o[0] == "SAckOK" for o in tcp.options))

            # Extract TCP options
            self.tcp_options = []
            for opt in tcp.options:
                self.tcp_options.append(opt[0])
                if opt[0] == "MSS":
                    self.mss = opt[1]
                elif opt[0] == "WScale":
                    self.wscale = opt[1]

            # Build options order string for fingerprinting
            self.options_order = ",".join(self.tcp_options)

        return self

    def signature_string(self) -> str:
        """Generate a compact fingerprint signature string."""
        return f"W{self.window_size}|TTL{self.ttl}|MSS{self.mss}|WS{self.wscale}|{'TS' if self.timestamp else 'noTS'}|{'SACK' if self.sack_perm else 'noSACK'}|{self.options_order}"


# Known service fingerprint database (protocol-level, not banner-based)
SERVICE_FINGERPRINTS = {
    # HTTP Services
    "HTTP-80": {
        "port": 80,
        "service": "http",
        "version": "unknown",
        "window_size": (8192, 65535),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    "HTTP-443": {
        "port": 443,
        "service": "https",
        "window_size": (8192, 65535),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # Apache
    "APACHE": {
        "port": None,
        "service": "apache",
        "version": "unknown",
        "window_size": (5840, 65535),
        "ttl_range": (40, 64),
        "mss": 1460,
        "options_order": ["MSS", "SAckOK", "Timestamp", "WScale"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # Nginx
    "NGINX": {
        "port": None,
        "service": "nginx",
        "version": "unknown",
        "window_size": (65535, 65535),
        "ttl_range": (40, 64),
        "mss": 1460,
        "options_order": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # Microsoft IIS/Windows
    "IIS": {
        "port": None,
        "service": "microsoft-iis",
        "version": "unknown",
        "window_size": (65535, 65535),
        "ttl_range": (100, 130),
        "mss": 1460,
        "options_order": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK", "Timestamp"],
        "os_hint": "windows",
        "protocol": "tcp",
    },
    # SSH
    "SSH": {
        "port": 22,
        "service": "ssh",
        "version": "unknown",
        "window_size": (5760, 32768),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    "OPENSSH": {
        "port": None,
        "service": "openssh",
        "version": "unknown",
        "window_size": (5760, 32768),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # FTP
    "FTP": {
        "port": 21,
        "service": "ftp",
        "version": "unknown",
        "window_size": (5760, 5840),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # MySQL
    "MYSQL": {
        "port": 3306,
        "service": "mysql",
        "version": "unknown",
        "window_size": (5840, 65535),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # PostgreSQL
    "POSTGRESQL": {
        "port": 5432,
        "service": "postgresql",
        "version": "unknown",
        "window_size": (5840, 65535),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # DNS
    "DNS": {
        "port": 53,
        "service": "dns",
        "version": "unknown",
        "window_size": (4096, 8192),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # SMB
    "SMB": {
        "port": 445,
        "service": "microsoft-ds",
        "version": "unknown",
        "window_size": (65535, 65535),
        "ttl_range": (100, 130),
        "mss": 1460,
        "options_order": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK", "Timestamp"],
        "os_hint": "windows",
        "protocol": "tcp",
    },
    # RPC
    "RPC": {
        "port": 111,
        "service": "rpcbind",
        "version": "unknown",
        "window_size": (8192, 65535),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # Redis
    "REDIS": {
        "port": 6379,
        "service": "redis",
        "version": "unknown",
        "window_size": (8192, 65535),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # MongoDB
    "MONGODB": {
        "port": 27017,
        "service": "mongodb",
        "version": "unknown",
        "window_size": (8192, 65535),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # RDP
    "RDP": {
        "port": 3389,
        "service": "ms-wbt-server",
        "version": "unknown",
        "window_size": (65535, 65535),
        "ttl_range": (100, 130),
        "mss": 1460,
        "options_order": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK", "Timestamp"],
        "os_hint": "windows",
        "protocol": "tcp",
    },
    # Telnet
    "TELNET": {
        "port": 23,
        "service": "telnet",
        "version": "unknown",
        "window_size": (5760, 5840),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # SMTP
    "SMTP": {
        "port": 25,
        "service": "smtp",
        "version": "unknown",
        "window_size": (8192, 65535),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # POP3
    "POP3": {
        "port": 110,
        "service": "pop3",
        "version": "unknown",
        "window_size": (5760, 5840),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # IMAP
    "IMAP": {
        "port": 143,
        "service": "imap",
        "version": "unknown",
        "window_size": (5760, 5840),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "tcp",
    },
    # NTP
    "NTP": {
        "port": 123,
        "service": "ntp",
        "version": "unknown",
        "window_size": (4096, 8192),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "udp",
    },
    # SNMP
    "SNMP": {
        "port": 161,
        "service": "snmp",
        "version": "unknown",
        "window_size": (4096, 8192),
        "ttl_range": (40, 128),
        "mss": 1460,
        "options_order": ["MSS", "WScale", "SAckOK", "Timestamp"],
        "os_hint": "linux",
        "protocol": "udp",
    },
}

# OS fingerprint database
OS_FINGERPRINTS = {
    "linux": {
        "ttl_range": (40, 64),
        "window_sizes": [5760, 5840, 8192, 65535],
        "df_flag": True,
        "typical_options": ["MSS", "WScale", "SAckOK", "Timestamp"],
    },
    "windows": {
        "ttl_range": (100, 130),
        "window_sizes": [65535, 8192],
        "df_flag": True,
        "typical_options": ["MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK", "Timestamp"],
    },
    "cisco": {
        "ttl_range": (240, 255),
        "window_sizes": [4128],
        "df_flag": False,
        "typical_options": ["MSS"],
    },
    "freebsd": {
        "ttl_range": (40, 64),
        "window_sizes": [65535],
        "df_flag": True,
        "typical_options": ["MSS", "WScale", "SAckOK", "Timestamp"],
    },
    "macos": {
        "ttl_range": (40, 64),
        "window_sizes": [65535],
        "df_flag": True,
        "typical_options": ["MSS", "WScale", "SAckOK", "Timestamp"],
    },
}
