"""
phantom-scan — Pivot Engine
=================================
Automatic proxy chain construction and multi-hop tunnel management
for post-exploitation network pivoting.

Core operations:
1. Discovers usable pivot points (compromised hosts, open proxies)
2. Constructs optimal proxy chains based on network topology
3. Manages multi-hop tunnel connections
4. Implements dynamic port forwarding
5. Optimizes routes based on latency, reliability, and detection risk

No AI — uses graph theory, network topology analysis, and
deterministic optimization algorithms.
"""

import logging
import heapq
from typing import Optional, List, Dict, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger("phantom-scan")


@dataclass
class ProxyNode:
    """Represents a potential proxy/pivot point."""

    host: str
    port: int
    service: str = "unknown"
    username: Optional[str] = None
    password: Optional[str] = None
    type: str = "http"  # http, socks4, socks5, ssh, telnet
    reachable: bool = True
    latency_ms: float = 0.0
    reliability: float = 1.0
    detection_risk: float = 0.0
    hops_from_target: int = 0
    is_compromised: bool = False
    os_hint: str = "unknown"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "type": self.type,
            "reachable": self.reachable,
            "latency_ms": self.latency_ms,
            "reliability": self.reliability,
            "detection_risk": self.detection_risk,
            "hops_from_target": self.hops_from_target,
            "is_compromised": self.is_compromised,
        }

    def connection_string(self) -> str:
        """Get connection string for this proxy."""
        if self.type == "http":
            return f"http://{self.host}:{self.port}"
        elif self.type == "socks5":
            return f"socks5://{self.host}:{self.port}"
        elif self.type == "socks4":
            return f"socks4://{self.host}:{self.port}"
        elif self.type == "ssh":
            return f"ssh://{self.username or 'root'}@{self.host}:{self.port}"
        elif self.type == "telnet":
            return f"telnet://{self.host}:{self.port}"
        return f"{self.host}:{self.port}"


@dataclass
class ProxyChain:
    """Represents a complete proxy chain."""

    nodes: List[ProxyNode] = field(default_factory=list)
    total_latency_ms: float = 0.0
    total_reliability: float = 1.0
    total_risk: float = 0.0
    path_length: int = 0

    def add_node(self, node: ProxyNode):
        """Add a node to the chain and recalculate metrics."""
        self.nodes.append(node)
        self.path_length = len(self.nodes)
        self.total_latency_ms += node.latency_ms
        self.total_reliability *= node.reliability
        self.total_risk += node.detection_risk

    def get_chained_url(self) -> str:
        """Get the chained URL representation."""
        if not self.nodes:
            return ""
        # Build chain notation: node1 -> node2 -> ... -> target
        chain_parts = [n.connection_string() for n in self.nodes]
        return " → ".join(chain_parts)

    def get_summary(self) -> dict:
        """Get chain summary metrics."""
        return {
            "path_length": self.path_length,
            "total_latency_ms": round(self.total_latency_ms, 2),
            "total_reliability": round(self.total_reliability, 4),
            "total_risk": round(self.total_risk, 4),
            "average_latency_ms": (
                round(self.total_latency_ms / self.path_length, 2) if self.path_length > 0 else 0
            ),
        }

    def __lt__(self, other):
        """Comparison for priority queue — lower risk and latency preferred."""
        if self.total_risk != other.total_risk:
            return self.total_risk < other.total_risk
        return self.total_latency_ms < other.total_latency_ms


@dataclass
class TunnelConfig:
    """Configuration for a tunnel."""

    local_port: int
    remote_host: str
    remote_port: int
    proxy_chain: List[ProxyNode]
    protocol: str = "tcp"  # tcp, udp
    encryption: bool = True
    persistent: bool = False
    timeout: int = 300

    def to_dict(self) -> dict:
        return {
            "local_port": self.local_port,
            "remote_host": self.remote_host,
            "remote_port": self.remote_port,
            "chain": [n.to_dict() for n in self.proxy_chain],
            "protocol": self.protocol,
            "encryption": self.encryption,
            "persistent": self.persistent,
            "timeout": self.timeout,
        }


# Network topology graph
class NetworkGraph:
    """
    Represents network topology as a weighted directed graph.

    Nodes are network hosts, edges are network connections.
    Weights represent latency, reliability, and detection risk.

    Uses Dijkstra's algorithm for shortest path finding.
    """

    def __init__(self):
        self.adjacency_list: Dict[str, List[Tuple[str, float, float, float]]] = defaultdict(list)
        self.nodes: Dict[str, dict] = {}
        self.edge_count = 0

    def add_edge(
        self, from_node: str, to_node: str, latency: float, reliability: float, risk: float
    ):
        """Add a weighted directed edge between two nodes."""
        self.adjacency_list[from_node].append((to_node, latency, reliability, risk))
        self.edge_count += 1

        if from_node not in self.nodes:
            self.nodes[from_node] = {"type": "host"}
        if to_node not in self.nodes:
            self.nodes[to_node] = {"type": "host"}

    def add_node(self, node_id: str, node_data: dict = None):
        """Add a node to the graph."""
        self.nodes[node_id] = node_data or {"type": "host"}

    def shortest_path(self, start: str, end: str) -> Optional[List[str]]:
        """
        Find shortest path using Dijkstra's algorithm.

        Weights: priority = risk * 10 + latency (risk-weighted shortest path)

        Returns:
            List of node IDs representing the path, or None if no path exists
        """
        if start not in self.nodes or end not in self.nodes:
            return None

        # Priority queue: (cost, node_id, path)
        pq = [(0, start, [start])]
        visited = set()

        while pq:
            cost, current, path = heapq.heappop(pq)

            if current == end:
                return path

            if current in visited:
                continue
            visited.add(current)

            for neighbor, latency, reliability, risk in self.adjacency_list[current]:
                if neighbor in visited:
                    continue

                # Weighted cost: prioritize low risk, then low latency
                edge_cost = risk * 10 + latency
                heapq.heappush(pq, (cost + edge_cost, neighbor, path + [neighbor]))

        return None

    def get_all_paths(self, start: str, end: str, max_paths: int = 5) -> List[List[str]]:
        """
        Find multiple paths between two nodes using k-shortest paths.

        Returns:
            List of paths, each path is a list of node IDs
        """
        paths = []
        if start not in self.nodes or end not in self.nodes:
            return paths

        # Use modified Dijkstra to find multiple paths
        # Simple approach: find shortest path, then exclude edges and re-find
        temp_graph = dict(self.adjacency_list)

        for _ in range(max_paths):
            path = self._find_kth_path(start, end, paths)
            if path:
                paths.append(path)
            else:
                break

        return paths

    def _find_kth_path(
        self, start: str, end: str, existing_paths: List[List[str]]
    ) -> Optional[List[str]]:
        """Find next shortest path avoiding edges in existing paths."""
        # BFS-based approach avoiding previously found paths' edges
        excluded_edges = set()
        for path in existing_paths:
            for i in range(len(path) - 1):
                excluded_edges.add((path[i], path[i + 1]))

        # Modified Dijkstra with edge exclusions
        pq = [(0, start, [start])]
        visited = set()

        while pq:
            cost, current, path = heapq.heappop(pq)

            if current == end:
                return path

            if current in visited:
                continue
            visited.add(current)

            for neighbor, latency, reliability, risk in self.adjacency_list[current]:
                if neighbor in visited:
                    continue
                if (current, neighbor) in excluded_edges:
                    continue

                edge_cost = risk * 10 + latency
                heapq.heappush(pq, (cost + edge_cost, neighbor, path + [neighbor]))

        return None

    def get_topology_summary(self) -> dict:
        """Get network topology statistics."""
        return {
            "total_nodes": len(self.nodes),
            "total_edges": self.edge_count,
            "node_list": list(self.nodes.keys()),
        }
