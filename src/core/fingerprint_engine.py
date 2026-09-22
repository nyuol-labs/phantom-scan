"""
phantom-scan — Service Fingerprint Engine
=============================================
Matches TCP response signatures against known service fingerprints.
Identifies services, versions, and operating systems purely from
protocol-level characteristics.
"""

import logging
from typing import Optional, Dict, List, Tuple
from dataclasses import dataclass

from src.modules.fingerprint import (
    ServiceFingerprint,
    ResponseSignature,
    SERVICE_FINGERPRINTS,
    OS_FINGERPRINTS,
)

logger = logging.getLogger("phantom-scan")


class ServiceFingerprinter:
    """
    Identifies services on open ports by analyzing TCP response signatures.

    Fingerprinting approach:
    1. Capture TCP response characteristics (window, TTL, options, MSS)
    2. Match against known service fingerprints
    3. Score confidence based on how many fields match
    4. Identify OS from TTL, window size, and option patterns
    5. Cross-reference port numbers with known services

    No banners are fetched — identification is purely through protocol analysis.
    """

    def __init__(self):
        self.fingerprints = SERVICE_FINGERPRINTS
        self.os_fingerprints = OS_FINGERPRINTS
        self.fingerprint_cache: Dict[str, ServiceFingerprint] = {}
        self.fingerprint_count = 0

    def analyze_response(self, packet, port: int, rtt: float) -> Optional[ServiceFingerprint]:
        """
        Analyze a TCP response packet to create a service fingerprint.
        """
        if packet is None:
            return None

        sig = ResponseSignature()
        sig.capture(packet)
        sig.rtt = rtt

        return self.fingerprint_port(sig, port)

        return self.fingerprint_port(sig, port)

    def fingerprint_port(
        self, signature: ResponseSignature, port: int
    ) -> Optional[ServiceFingerprint]:
        """
        Match a response signature against known fingerprints for a specific port.

        Args:
            signature: Captured response signature
            port: Target port number

        Returns:
            ServiceFingerprint with identified service
        """
        # Build cache key
        cache_key = signature.signature_string()

        # Check cache first
        if cache_key in self.fingerprint_cache:
            cached = self.fingerprint_cache[cache_key]
            if cached.port == port:
                return cached

        # Find matching fingerprints
        matches = self._find_matches(signature, port)

        if matches:
            best = self._select_best_match(matches, signature)
            self.fingerprint_cache[cache_key] = best
            self.fingerprint_count += 1
            return best

        # Unknown service — create generic fingerprint
        unknown = self._create_unknown(signature, port)
        return unknown

    def _find_matches(
        self, signature: ResponseSignature, port: int
    ) -> List[Tuple[ServiceFingerprint, float]]:
        """
        Find all service fingerprints that match the response signature.

        Returns list of (fingerprint, confidence_score) tuples.
        """
        matches = []

        for fp_name, fp_data in self.fingerprints.items():
            score = self._calculate_match_score(signature, fp_data, port)

            if score > 0.0:
                fp = ServiceFingerprint(
                    port=port or fp_data.get("port", 0),
                    service=fp_data["service"],
                    version=fp_data.get("version", "unknown"),
                    confidence=score,
                    fingerprint_data={
                        "window_size": signature.window_size,
                        "ttl": signature.ttl,
                        "mss": signature.mss,
                        "wscale": signature.wscale,
                        "options_order": signature.options_order,
                        "timestamp": signature.timestamp,
                        "sack_perm": signature.sack_perm,
                    },
                    os_hint=fp_data.get("os_hint", "unknown"),
                    details={"fp_name": fp_name},
                )
                matches.append((fp, score))

        return matches

    def _calculate_match_score(
        self, signature: ResponseSignature, fp_data: dict, port: int
    ) -> float:
        """
        Calculate match score between a response signature and a fingerprint.

        Scoring weights:
        - Port match: 40%
        - Window size match: 25%
        - TTL range match: 15%
        - MSS match: 10%
        - Options order match: 10%

        Returns score between 0.0 and 1.0.
        """
        score = 0.0

        # Port match (40%)
        if fp_data.get("port") and port == fp_data["port"]:
            score += 0.40

        # Window size match (25%)
        if "window_size" in fp_data:
            ws_min, ws_max = fp_data["window_size"]
            if ws_min <= signature.window_size <= ws_max:
                score += 0.25

        # TTL range match (15%)
        if "ttl_range" in fp_data:
            ttl_min, ttl_max = fp_data["ttl_range"]
            if ttl_min <= signature.ttl <= ttl_max:
                score += 0.15

        # MSS match (10%)
        if "mss" in fp_data:
            if signature.mss == fp_data["mss"] or signature.mss == 0:
                score += 0.10

        # Options order match (10%)
        if "options_order" in fp_data:
            expected = fp_data["options_order"]
            if signature.options_order:
                # Check if expected options appear in observed order
                if self._options_match(signature.options_order, expected):
                    score += 0.10

        return min(1.0, score)

    def _options_match(self, observed: str, expected) -> bool:
        """Check if observed options match expected pattern."""
        if not observed:
            return False
        observed_opts = [o.strip() for o in observed.split(",")]
        # Handle both string and list expected values
        if isinstance(expected, str):
            expected_opts = [o.strip() for o in expected.split(",")]
        elif isinstance(expected, list):
            expected_opts = [str(o).strip() for o in expected]
        else:
            return False
        return all(opt in observed_opts for opt in expected_opts)

    def _select_best_match(
        self, matches: List[Tuple[ServiceFingerprint, float]], sig: ResponseSignature
    ) -> ServiceFingerprint:
        """Select the highest-confidence match from a list."""
        if not matches:
            return self._create_unknown(sig, sig.rtt)

        # Sort by confidence descending
        matches.sort(key=lambda x: x[1], reverse=True)
        best_fp, best_score = matches[0]
        best_fp.confidence = best_score

        # Identify OS
        best_fp.os_hint = self._identify_os(sig)

        logger.info(
            f"  [FINGERPRINT] Port {best_fp.port}: {best_fp.service} "
            f"(confidence: {best_score:.2f}, OS: {best_fp.os_hint})"
        )

        return best_fp

    def _identify_os(self, signature: ResponseSignature) -> str:
        """
        Identify the operating system from TCP response characteristics.

        Uses TTL, window size, DF flag, and option patterns.
        """
        best_os = "unknown"
        best_score = 0.0

        for os_name, os_data in self.os_fingerprints.items():
            score = 0.0

            # TTL match
            ttl_min, ttl_max = os_data["ttl_range"]
            if ttl_min <= signature.ttl <= ttl_max:
                score += 0.4

            # Window size match
            if signature.window_size in os_data["window_sizes"]:
                score += 0.3

            # DF flag match
            if signature.df_flag == os_data["df_flag"]:
                score += 0.2

            # Options pattern match
            if signature.options_order:
                observed_opts = [o.strip() for o in signature.options_order.split(",")]
                expected_opts = [o.strip() for o in os_data["typical_options"]]
                if all(opt in observed_opts for opt in expected_opts):
                    score += 0.1

            if score > best_score:
                best_score = score
                best_os = os_name

        return best_os

    def _create_unknown(self, signature: ResponseSignature, port: int) -> ServiceFingerprint:
        """Create a fingerprint for an unidentified service."""
        os_name = self._identify_os(signature)

        return ServiceFingerprint(
            port=port,
            service="unknown",
            version="unknown",
            confidence=0.0,
            fingerprint_data={
                "window_size": signature.window_size,
                "ttl": signature.ttl,
                "mss": signature.mss,
                "wscale": signature.wscale,
                "options_order": signature.options_order,
                "timestamp": signature.timestamp,
                "sack_perm": signature.sack_perm,
            },
            os_hint=os_name,
            details={"note": "No known fingerprint matched"},
        )

    def get_fingerprint_report(self) -> dict:
        """Generate a summary report of all fingerprints collected."""
        services = {}
        for fp in self.fingerprint_cache.values():
            port = fp.port
            if port not in services:
                services[port] = fp.to_dict()
            else:
                # Update existing if confidence is higher
                if fp.confidence > services[port]["confidence"]:
                    services[port] = fp.to_dict()

        return {
            "total_fingerprints": self.fingerprint_count,
            "services_found": len(services),
            "services": services,
        }
