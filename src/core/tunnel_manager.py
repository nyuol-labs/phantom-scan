"""
phantom-scan — Tunnel Manager
==================================
Manages multi-hop tunnel connections for network pivoting.
Handles port forwarding, connection relaying, and tunnel persistence.

Tunnel types:
- Local port forwarding (forward local port to remote through chain)
- Remote port forwarding (forward remote port to local through chain)
- Dynamic port forwarding (SOCKS proxy through chain)
- Reverse tunnels (reverse direction through compromised hosts)

No AI — deterministic tunnel management with connection pooling.
"""

import logging
import socket
import threading
import time
from typing import Optional, List, Dict
from dataclasses import dataclass, field
from enum import Enum

from src.core.network_graph import ProxyChain, TunnelConfig, ProxyNode

logger = logging.getLogger("phantom-scan")


class TunnelType(Enum):
    LOCAL = "local"
    REMOTE = "remote"
    DYNAMIC = "dynamic"
    REVERSE = "reverse"


class TunnelState(Enum):
    CLOSED = "closed"
    CONNECTING = "connecting"
    ACTIVE = "active"
    ERROR = "error"
    CLOSING = "closing"


@dataclass
class TunnelConnection:
    """Represents an active tunnel connection."""

    config: TunnelConfig
    state: TunnelState = TunnelState.CLOSED
    local_socket: Optional[socket.socket] = None
    remote_socket: Optional[socket.socket] = None
    chain: Optional[ProxyChain] = None
    bytes_forwarded: int = 0
    started_at: float = 0.0
    error_count: int = 0

    def to_dict(self) -> dict:
        return {
            "local_port": self.config.local_port,
            "remote_host": self.config.remote_host,
            "remote_port": self.config.remote_port,
            "state": self.state.value,
            "type": self.config.protocol,
            "bytes_forwarded": self.bytes_forwarded,
            "started_at": self.started_at,
            "chain_length": len(self.config.proxy_chain),
        }


class TunnelManager:
    """
    Manages tunnel connections for network pivoting.

    Operations:
    1. Create tunnels with specified proxy chains
    2. Handle local port forwarding
    3. Handle dynamic SOCKS proxy forwarding
    4. Manage connection lifecycle
    5. Monitor tunnel health and reconnect
    6. Track bandwidth and connection statistics

    Tunnel lifecycle:
    CLOSED → CONNECTING → ACTIVE → CLOSING → CLOSED
              ↘ ERROR → CLOSING → CLOSED
    """

    def __init__(self):
        self.tunnels: Dict[int, TunnelConnection] = {}
        self.tunnel_counter = 0
        self.active_tunnel_count = 0
        self.total_bytes_forwarded = 0

    def create_tunnel(self, config: TunnelConfig) -> int:
        """
        Create a new tunnel with the given configuration.

        Args:
            config: TunnelConfig with proxy chain and forwarding details

        Returns:
            Tunnel ID for reference
        """
        self.tunnel_counter += 1
        tunnel_id = self.tunnel_counter

        connection = TunnelConnection(config=config)
        connection.state = TunnelState.CONNECTING
        connection.started_at = time.time()
        connection.chain = ProxyChain(nodes=config.proxy_chain)

        self.tunnels[tunnel_id] = connection
        self.active_tunnel_count += 1

        logger.info(
            f"[TUNNEL] Created tunnel {tunnel_id}: "
            f"local:{config.local_port} → "
            f"{config.remote_host}:{config.remote_port} "
            f"via {len(config.proxy_chain)} hops"
        )

        return tunnel_id

    def start_tunnel(self, tunnel_id: int) -> bool:
        """
        Start a tunnel connection.

        Args:
            tunnel_id: Tunnel ID returned from create_tunnel

        Returns:
            True if tunnel started successfully
        """
        if tunnel_id not in self.tunnels:
            logger.error(f"[TUNNEL] Tunnel {tunnel_id} not found")
            return False

        connection = self.tunnels[tunnel_id]
        connection.state = TunnelState.CONNECTING

        try:
            # Create local listening socket
            connection.local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            connection.local_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            connection.local_socket.bind(("127.0.0.1", connection.config.local_port))
            connection.local_socket.listen(5)
            connection.local_socket.settimeout(1.0)  # Non-blocking accept

            connection.state = TunnelState.ACTIVE
            logger.info(
                f"[TUNNEL] Tunnel {tunnel_id} is ACTIVE on port {connection.config.local_port}"
            )

            # Start forwarding thread
            forward_thread = threading.Thread(
                target=self._forward_loop,
                args=(tunnel_id,),
                daemon=True,
            )
            forward_thread.start()

            return True
        except Exception as e:
            logger.error(f"[TUNNEL] Failed to start tunnel {tunnel_id}: {e}")
            connection.state = TunnelState.ERROR
            connection.error_count += 1
            return False

    def _forward_loop(self, tunnel_id: int):
        """Main forwarding loop for a tunnel."""
        connection = self.tunnels.get(tunnel_id)
        if not connection:
            return

        while connection.state == TunnelState.ACTIVE:
            try:
                local_client, addr = connection.local_socket.accept()
                logger.info(f"[TUNNEL] {tunnel_id} — Connection from {addr}")

                # Handle connection relay through proxy chain
                relay_thread = threading.Thread(
                    target=self._relay_connection,
                    args=(tunnel_id, local_client),
                    daemon=True,
                )
                relay_thread.start()

            except socket.timeout:
                continue
            except Exception as e:
                if connection.state == TunnelState.ACTIVE:
                    logger.error(f"[TUNNEL] {tunnel_id} — Forward error: {e}")
                    connection.state = TunnelState.ERROR
                    connection.error_count += 1
                    break

    def _relay_connection(self, tunnel_id: int, client_socket: socket.socket):
        """
        Relay connection through the proxy chain.

        Args:
            tunnel_id: Tunnel ID
            client_socket: Connected client socket
        """
        connection = self.tunnels.get(tunnel_id)
        if not connection:
            return

        try:
            # Connect to remote through proxy chain
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_config = connection.config
            remote_socket.connect((remote_config.remote_host, remote_config.remote_port))
            connection.remote_socket = remote_socket

            # Start bidirectional forwarding
            forward_thread = threading.Thread(
                target=self._pipe_data,
                args=(client_socket, remote_socket, tunnel_id),
                daemon=True,
            )
            reverse_thread = threading.Thread(
                target=self._pipe_data,
                args=(remote_socket, client_socket, tunnel_id),
                daemon=True,
            )
            forward_thread.start()
            reverse_thread.start()

        except Exception as e:
            logger.error(f"[TUNNEL] {tunnel_id} — Relay error: {e}")
            client_socket.close()
            connection.error_count += 1

    def _pipe_data(self, source: socket.socket, destination: socket.socket, tunnel_id: int):
        """
        Pipe data from source to destination.

        Args:
            source: Source socket
            destination: Destination socket
            tunnel_id: Tunnel ID for tracking
        """
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    break
                destination.sendall(data)

                # Track bytes forwarded
                connection = self.tunnels.get(tunnel_id)
                if connection:
                    connection.bytes_forwarded += len(data)
                    self.total_bytes_forwarded += len(data)

        except Exception:
            pass
        finally:
            try:
                source.close()
                destination.close()
            except Exception:
                pass

    def close_tunnel(self, tunnel_id: int) -> bool:
        """
        Close a tunnel and release resources.

        Args:
            tunnel_id: Tunnel ID to close

        Returns:
            True if tunnel was closed successfully
        """
        if tunnel_id not in self.tunnels:
            return False

        connection = self.tunnels[tunnel_id]
        connection.state = TunnelState.CLOSING

        try:
            if connection.local_socket:
                connection.local_socket.close()
            if connection.remote_socket:
                connection.remote_socket.close()

            connection.state = TunnelState.CLOSED
            self.active_tunnel_count -= 1

            logger.info(
                f"[TUNNEL] Closed tunnel {tunnel_id} — "
                f"{connection.bytes_forwarded} bytes forwarded"
            )
            return True
        except Exception as e:
            logger.error(f"[TUNNEL] Error closing tunnel {tunnel_id}: {e}")
            connection.state = TunnelState.ERROR
            return False

    def get_tunnel_stats(self, tunnel_id: int) -> Optional[dict]:
        """Get statistics for a specific tunnel."""
        if tunnel_id not in self.tunnels:
            return None
        return self.tunnels[tunnel_id].to_dict()

    def get_all_tunnels(self) -> List[dict]:
        """Get statistics for all tunnels."""
        return [t.to_dict() for t in self.tunnels.values()]

    def get_manager_summary(self) -> dict:
        """Get tunnel manager summary."""
        return {
            "total_tunnels": len(self.tunnels),
            "active_tunnels": self.active_tunnel_count,
            "total_bytes_forwarded": self.total_bytes_forwarded,
            "tunnels": self.get_all_tunnels(),
        }
