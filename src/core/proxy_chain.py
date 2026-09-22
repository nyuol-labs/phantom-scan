"""
phantom-scan — Proxy Chain Builder
=========================================
Constructs optimal proxy chains from discovered network nodes.
Automatically determines the best path through compromised hosts
based on latency, reliability, and detection risk.

Chain construction algorithm:
1. Collect all available proxy nodes
2. Build network topology graph
3. Run shortest-path algorithm to find optimal chains
4. Filter by security constraints (max hops, max risk)
5. Generate chain configuration for tunnel management
"""

import logging
from typing import Optional, List, Dict
from dataclasses import dataclass, field

from src.core.network_graph import NetworkGraph, ProxyNode, ProxyChain

logger = logging.getLogger("phantom-scan")


class ProxyChainBuilder:
    """
    Constructs optimal proxy chains from discovered pivot points.

    Workflow:
    1. Receive list of available proxy nodes
    2. Build network topology graph from discovered hosts
    3. Find optimal paths using Dijkstra's algorithm
    4. Generate proxy chains sorted by priority
    5. Apply security constraints (max hops, max risk)
    """

    def __init__(self):
        self.graph = NetworkGraph()
        self.available_nodes: Dict[str, ProxyNode] = {}
        self.chain_cache: Dict[str, ProxyChain] = {}

    def discover_nodes(self, scan_results: List[dict]) -> List[ProxyNode]:
        """
        Discover proxy nodes from scan results.

        Args:
            scan_results: List of scan result dictionaries

        Returns:
            List of discovered proxy nodes
        """
        discovered = []

        for result in scan_results:
            if result.get("state") != "open":
                continue

            port = result["port"]
            fingerprint = result.get("fingerprint")

            if not fingerprint:
                continue

            service = fingerprint.get("service", "unknown")
            os_hint = fingerprint.get("os_hint", "unknown")
            host = result.get("target", "unknown")

            # Determine proxy type based on service
            proxy_type = self._service_to_proxy_type(service)

            if proxy_type is None:
                continue

            node = ProxyNode(
                host=host,
                port=port,
                service=service,
                type=proxy_type,
                os_hint=os_hint,
                is_compromised=(os_hint != "unknown"),
                latency_ms=self._estimate_latency(os_hint),
                reliability=self._estimate_reliability(service),
                detection_risk=self._estimate_detection_risk(service),
            )
            discovered.append(node)
            self.available_nodes[f"{host}:{port}"] = node

            logger.info(
                f"[DISCOVER] Pivot node: {host}:{port} ({proxy_type}, "
                f"latency: {node.latency_ms:.1f}ms, risk: {node.detection_risk:.2f})"
            )

        return discovered

    def build_topology(self, nodes: List[ProxyNode]):
        """
        Build network topology graph from discovered nodes.

        Creates edges between all discoverable nodes.
        """
        self.graph = NetworkGraph()

        # Add all nodes to graph
        for node in nodes:
            self.graph.add_node(node.host, {"proxy_type": node.type, "port": node.port})

        # Create edges between nodes (fully connected for now)
        for i, node_a in enumerate(nodes):
            for j, node_b in enumerate(nodes):
                if i == j:
                    continue
                # Edge weight based on estimated network characteristics
                latency = abs(node_a.latency_ms - node_b.latency_ms) + 5.0
                reliability = min(node_a.reliability, node_b.reliability)
                risk = node_a.detection_risk + node_b.detection_risk
                self.graph.add_edge(node_a.host, node_b.host, latency, reliability, risk)

        logger.info(
            f"[TOPOLOGY] Built graph with {len(nodes)} nodes, {self.graph.edge_count} edges"
        )

    def build_chains(
        self, target: str, max_hops: int = 3, max_risk: float = 5.0
    ) -> List[ProxyChain]:
        """
        Build optimal proxy chains to target.

        Args:
            target: Target host to reach through proxies
            max_hops: Maximum number of proxy hops
            max_risk: Maximum acceptable detection risk

        Returns:
            List of ProxyChain objects sorted by priority
        """
        chains = []

        if not self.graph.nodes:
            logger.warning("[CHAIN] No topology graph built yet")
            return chains

        # Find all paths from available nodes to target
        for node_id in self.graph.nodes:
            path = self.graph.shortest_path(node_id, target)
            if path and len(path) <= max_hops + 1:  # +1 for target
                chain = self._path_to_chain(path)
                if chain and chain.total_risk <= max_risk:
                    chains.append(chain)

        # Sort by priority (lower risk and latency first)
        chains.sort()

        # Cache chains
        for chain in chains:
            cache_key = chain.get_chained_url()
            self.chain_cache[cache_key] = chain

        logger.info(f"[CHAIN] Built {len(chains)} chains to {target} (max_hops={max_hops})")
        return chains

    def get_optimal_chain(self, target: str, max_hops: int = 3) -> Optional[ProxyChain]:
        """
        Get the single optimal proxy chain to target.

        Returns:
            Best ProxyChain or None if no valid chain exists
        """
        chains = self.build_chains(target, max_hops=max_hops)
        if chains:
            return chains[0]
        return None

    def _path_to_chain(self, path: List[str]) -> Optional[ProxyChain]:
        """Convert a node path to a ProxyChain."""
        if len(path) < 2:
            return None

        chain = ProxyChain()
        for node_id in path:
            if node_id in self.available_nodes:
                node = self.available_nodes[node_id]
                chain.add_node(node)

        if chain.path_length > 0:
            return chain
        return None

    def _service_to_proxy_type(self, service: str) -> Optional[str]:
        """Map discovered service to proxy type."""
        proxy_map = {
            "http": "http",
            "https": "http",
            "socks": "socks5",
            "ssh": "ssh",
            "telnet": "telnet",
            "smtp": "http",
            "ftp": "http",
            "rpcbind": "socks5",
            "redis": "socks5",
            "microsoft-ds": "socks5",
        }
        return proxy_map.get(service.lower())

    def _estimate_latency(self, os_hint: str) -> float:
        """Estimate latency based on OS hint."""
        latency_map = {
            "linux": 10.0,
            "windows": 15.0,
            "macos": 12.0,
            "freebsd": 11.0,
            "cisco": 20.0,
        }
        return latency_map.get(os_hint.lower(), 15.0)

    def _estimate_reliability(self, service: str) -> float:
        """Estimate proxy reliability based on service type."""
        reliable_services = {"ssh", "http", "https"}
        return 0.95 if service in reliable_services else 0.80

    def _estimate_detection_risk(self, service: str) -> float:
        """Estimate detection risk based on service type."""
        low_risk = {"ssh", "https"}
        medium_risk = {"http", "smtp"}
        if service in low_risk:
            return 0.2
        elif service in medium_risk:
            return 0.5
        else:
            return 0.7

    def get_chain_report(self) -> dict:
        """Generate a report of all available chains."""
        return {
            "total_nodes": len(self.available_nodes),
            "total_chains": len(self.chain_cache),
            "chains": {key: chain.get_summary() for key, chain in self.chain_cache.items()},
        }
