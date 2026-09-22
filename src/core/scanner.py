"""
phantom-scan — Scanner Core
===========================
Main scanning orchestration engine. Coordinates timing, probing,
service fingerprinting, protocol state analysis, and output generation.
"""

import sys
import time
import signal
import logging
from typing import Optional, List, Dict
from scapy.all import sr1, IP, TCP, ICMP, conf
from scapy.error import Scapy_Exception

from src.core.config import Config
from src.core.timing import AdaptiveTimer
from src.core.fingerprint_engine import ServiceFingerprinter
from src.core.protocol_state import ProtocolStateAnalyzer
from src.modules.passive import PassiveRecon

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("phantom-scan")


class PhantomScanner:
    """
    Main scanner class that orchestrates all scanning activities.

    Uses adaptive timing to evade detection while maintaining
    effective reconnaissance coverage. Integrates service fingerprinting
    and protocol state analysis for comprehensive network intelligence.
    """

    def __init__(self, config: Config):
        self.config = config
        self.config.validate()
        self.timer = AdaptiveTimer(config)
        self.passive = PassiveRecon(config)
        self.fingerprinter = ServiceFingerprinter()
        self.protocol_analyzer = ProtocolStateAnalyzer()
        self.results: Dict = {}
        self.running = False
        self.fingerprint_results: Dict = {}
        self._setup_signal_handlers()

        # Suppress scapy verbose output
        conf.verb = 0

    def _setup_signal_handlers(self):
        """Handle graceful shutdown."""
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

    def _signal_handler(self, signum, frame):
        """Handle interrupt signals."""
        logger.info("\n[!] Shutting down gracefully...")
        self.running = False

    def _send_probe(self, target: str, port: int) -> Optional:
        """
        Send a single stealth probe to a target port.
        Returns the response packet or None.
        """
        try:
            packet = IP(dst=target) / TCP(dport=port, flags="S", seq=1000)
            response = sr1(packet, timeout=2, verbose=0)
            return response
        except Scapy_Exception as e:
            logger.debug(f"Probe error to {target}:{port} — {e}")
            return None

    def _classify_response(self, response, target: str, port: int) -> dict:
        """
        Classify a response packet into a port state.
        """
        if response is None:
            return {"port": port, "state": "filtered", "service": None}

        if response.haslayer(TCP):
            tcp_layer = response.getlayer(TCP)
            if tcp_layer.flags == 0x12:  # SYN-ACK
                # Send RST to close without completing handshake
                rst = IP(dst=target) / TCP(dport=port, flags="R", seq=tcp_layer.ack)
                sr1(rst, timeout=1, verbose=0)
                return {"port": port, "state": "open", "service": None}
            elif tcp_layer.flags == 0x14:  # RST-ACK
                return {"port": port, "state": "closed", "service": None}

        if response.haslayer(ICMP):
            return {"port": port, "state": "filtered", "service": None}

        return {"port": port, "state": "unknown", "service": None}

    def _fingerprint_service(self, packet, port: int, rtt: float) -> Optional:
        """
        Fingerprint a service on an open port.
        """
        try:
            fp = self.fingerprinter.analyze_response(packet, port, rtt)
            if fp:
                return fp.to_dict()
        except Exception as e:
            logger.debug(f"Fingerprint error on port {port}: {e}")
        return None

    def _analyze_protocol(self, packet):
        """Feed packet into protocol state analyzer."""
        try:
            self.protocol_analyzer.observe_packet(packet)
        except Exception as e:
            logger.debug(f"Protocol analysis error: {e}")

    def scan_port(self, target: str, port: int) -> dict:
        """
        Scan a single port using adaptive timing with fingerprinting.
        """
        self.timer.wait_for_next_probe()
        start = time.time()

        response = self._send_probe(target, port)
        rtt_ms = (time.time() - start) * 1000

        result = self._classify_response(response, target, port)

        # Record response for adaptive timing
        response_code = 0 if result["state"] == "open" else 100
        packet_size = len(response) if response else 0
        self.timer.record_response(rtt_ms, response_code, packet_size)

        result["rtt_ms"] = round(rtt_ms, 2)

        # Fingerprint service on open ports
        if result["state"] == "open" and response:
            fp_result = self._fingerprint_service(response, port, rtt_ms)
            result["fingerprint"] = fp_result
            if fp_result:
                logger.info(
                    f"  [FINGERPRINT] {target}:{port} — {fp_result['service']} "
                    f"(confidence: {fp_result['confidence']:.2f}, OS: {fp_result['os_hint']})"
                )

        # Analyze protocol state
        if response:
            self._analyze_protocol(response)

        return result

    def scan_target(self, target: str) -> List[dict]:
        """
        Scan all configured ports on a single target.
        """
        port_start, port_end = self.config.parsed_ports
        results = []
        open_ports = []

        logger.info(f"[*] Scanning {target} (ports {port_start}-{port_end})...")

        for port in range(port_start, port_end + 1):
            if not self.running:
                break

            result = self.scan_port(target, port)
            results.append(result)

            if result["state"] == "open":
                open_ports.append(port)
                logger.info(f"  [OPEN] {target}:{port} (RTT: {result['rtt_ms']}ms)")
                if "fingerprint" in result and result["fingerprint"]:
                    svc = result["fingerprint"]["service"]
                    os_hint = result["fingerprint"]["os_hint"]
                    logger.info(f"         → {svc} (OS: {os_hint})")

            # Progress update
            if self.config.verbose and port % 100 == 0:
                stats = self.timer.get_stats()
                logger.info(
                    f"  Progress: {port}/{port_end} | Interval: {stats['current_interval_ms']:.1f}ms"
                )

        return results

    def run(self):
        """Execute the full scan."""
        config = self.config

        if config.passive:
            logger.info("[*] Passive reconnaissance mode enabled")
            self.passive.run()
            return

        config.validate()
        self.running = True

        logger.info(f"[*] phantom-scan starting — Target: {config.target}")
        logger.info(f"[*] Timing: min_rtt={config.min_rtt_ms}ms, jitter={config.max_jitter_ms}ms")
        logger.info(f"[*] Adaptive mode: {'enabled' if not config.passive else 'disabled'}")
        logger.info(f"[*] Service fingerprinting: enabled")

        target = config.target
        results = self.scan_target(target)

        # Print protocol anomalies
        anomalies = self.protocol_analyzer.get_anomalies()
        if anomalies:
            logger.info(f"\n[!] {len(anomalies)} protocol anomalies detected:")
            for a in anomalies[:10]:
                logger.info(f"    Port {a['port']}: {a['anomaly']}")

        # Generate report
        self._generate_report(results)

        stats = self.timer.get_stats()
        fp_report = self.fingerprinter.get_fingerprint_report()
        logger.info(f"\n[+] Scan complete — {stats['probe_count']} probes sent")
        logger.info(
            f"[+] Detection risk: {stats['detection_risk']:.2f} | Avg interval: {stats['current_interval_ms']:.1f}ms"
        )
        logger.info(f"[+] Open ports found: {sum(1 for r in results if r['state'] == 'open')}")
        logger.info(f"[+] Services fingerprinted: {fp_report['services_found']}")
        logger.info(f"[+] Protocol anomalies: {len(anomalies)}")

        self.running = False

    def _generate_report(self, results: List[dict]):
        """Generate scan report."""
        open_results = [r for r in results if r["state"] == "open"]
        fp_report = self.fingerprinter.get_fingerprint_report()

        if self.config.output:
            import json

            report = {
                "target": self.config.target,
                "scan_stats": self.timer.get_stats(),
                "open_ports": open_results,
                "fingerprint_report": fp_report,
                "protocol_report": self.protocol_analyzer.get_protocol_report(),
            }
            with open(self.config.output, "w") as f:
                json.dump(report, f, indent=2)
            logger.info(f"[+] Report saved to {self.config.output}")
        else:
            if open_results:
                print(f"\n{'PORT':<8} {'STATE':<12} {'RTT (ms)':<12} {'SERVICE':<16} {'OS':<12}")
                print("-" * 60)
                for r in open_results:
                    svc = r.get("fingerprint", {}).get("service", "unknown")
                    os_hint = r.get("fingerprint", {}).get("os_hint", "unknown")
                    print(
                        f"{r['port']:<8} {r['state']:<12} {r['rtt_ms']:<12} {svc:<16} {os_hint:<12}"
                    )


if __name__ == "__main__":
    from src.core.cli import main

    main()
