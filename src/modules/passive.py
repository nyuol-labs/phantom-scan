"""
phantom-scan — Passive Reconnaissance Module
=============================================
Passive intelligence gathering without generating active probe traffic.
Uses sniffing, ARP monitoring, and DNS analysis to build a picture
of the target network.
"""

import logging
from typing import Optional, List, Dict
from scapy.all import sniff, ARP, IP, TCP, DNS, DNSQR, conf

logger = logging.getLogger("phantom-scan")


class PassiveRecon:
    """
    Passive network reconnaissance engine.

    Gathers information by observing existing traffic rather than
    generating probes. This makes it effectively undetectable.
    """

    def __init__(self, config):
        self.config = config
        self.discovered_hosts: Dict[str, dict] = {}
        self.discovered_services: Dict[int, dict] = {}
        self.dns_queries: List[str] = []
        self.packets_observed = 0

    def _packet_handler(self, packet):
        """Process each captured packet for intelligence."""
        self.packets_observed += 1

        # ARP discovery
        if packet.haslayer(ARP):
            self._process_arp(packet)

        # Host discovery via IP
        if packet.haslayer(IP):
            self._process_ip(packet)

        # DNS intelligence
        if packet.haslayer(DNS):
            self._process_dns(packet)

        # Service detection via TCP flags
        if packet.haslayer(TCP):
            self._process_tcp(packet)

    def _process_arp(self, packet):
        """Extract host information from ARP packets."""
        arp = packet[ARP]
        if arp.op == 1:  # ARP request
            if arp.psrc != "0.0.0.0":
                ip = arp.psrc
                if ip not in self.discovered_hosts:
                    self.discovered_hosts[ip] = {"mac": arp.hwsrc, "first_seen": None}
                    logger.info(f"  [PASSIVE] Discovered host: {ip} ({arp.hwsrc})")

        elif arp.op == 2:  # ARP reply
            ip = arp.psrc
            self.discovered_hosts[ip] = {"mac": arp.hwsrc, "first_seen": None}

    def _process_ip(self, packet):
        """Track hosts from IP traffic."""
        ip_layer = packet[IP]
        src = ip_layer.src
        dst = ip_layer.dst

        if src not in self.discovered_hosts:
            self.discovered_hosts[src] = {"ip": src, "first_seen": None}
        if dst not in self.discovered_hosts and dst != "255.255.255.255":
            self.discovered_hosts[dst] = {"ip": dst, "first_seen": None}

    def _process_dns(self, packet):
        """Extract DNS query intelligence."""
        dns = packet[DNS]
        if dns.qdcount > 0:
            for i in range(dns.qdcount):
                query = dns.qd[i].qname.decode("utf-8").rstrip(".")
                if query not in self.dns_queries:
                    self.dns_queries.append(query)
                    logger.info(f"  [PASSIVE] DNS query: {query}")

    def _process_tcp(self, packet):
        """Detect services from TCP traffic patterns."""
        tcp = packet[TCP]
        dport = tcp.dport
        if dport not in self.discovered_services:
            self.discovered_services[dport] = {
                "port": dport,
                "traffic_count": 0,
                "protocol": "tcp",
            }
            logger.info(f"  [PASSIVE] Service detected on port: {dport}")

    def run(self, duration: int = 30):
        """
        Run passive reconnaissance for a specified duration.

        Args:
            duration: Number of seconds to sniff (default: 30)
        """
        logger.info(f"[*] Passive reconnaissance starting (duration: {duration}s)...")
        logger.info(f"[*] Monitoring interface: {self.config.interface or 'default'}")

        sniff(
            iface=self.config.interface,
            prn=self._packet_handler,
            timeout=duration,
            store=False,
            filter="arp or ip or dns or tcp",
        )

        self._print_summary()

    def _print_summary(self):
        """Print reconnaissance summary."""
        print(f"\n{'='*50}")
        print(f"PASSIVE RECONNAISSANCE SUMMARY")
        print(f"{'='*50}")
        print(f"Hosts discovered:    {len(self.discovered_hosts)}")
        print(f"Services detected:   {len(self.discovered_services)}")
        print(f"DNS queries captured: {len(self.dns_queries)}")
        print(f"Packets observed:    {self.packets_observed}")

        if self.discovered_hosts:
            print(f"\nDiscovered Hosts:")
            for ip, info in self.discovered_hosts.items():
                mac = info.get("mac", "N/A")
                print(f"  {ip:<20} {mac}")

        if self.dns_queries:
            print(f"\nKey DNS Queries:")
            for q in self.dns_queries[:20]:
                print(f"  {q}")

        print(f"{'='*50}\n")
