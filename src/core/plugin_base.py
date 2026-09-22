"""
phantom-scan — Plugin System
=================================
Third-party module support framework for extending phantom-scan.

Plugin architecture:
- Standardized plugin interface (base classes)
- Dynamic loading and unloading of plugins
- Plugin lifecycle management (load, init, run, unload)
- Version compatibility checking
- Dependency resolution
- Community signature library sharing

Plugin types:
- ScannerPlugin — Custom scanning modules
- FingerprintPlugin — Additional service fingerprints
- ExploitPlugin — Custom exploit modules
- PayloadPlugin — Custom payload generators
- OutputPlugin — Custom output/report formatters
- PostModule — Post-exploitation modules

No AI — pure plugin architecture with Python importlib.
"""

import importlib
import importlib.util
import logging
import os
import sys
from typing import Optional, List, Dict, Type
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

logger = logging.getLogger("phantom-scan")


class PluginType(str, Enum):
    SCANNER = "scanner"
    FINGERPRINT = "fingerprint"
    EXPLOIT = "exploit"
    PAYLOAD = "payload"
    OUTPUT = "output"
    POST_MODULE = "post_module"


class PluginState(str, Enum):
    LOADED = "loaded"
    INITIALIZED = "initialized"
    ACTIVE = "active"
    DISABLED = "disabled"
    ERROR = "error"
    UNLOADED = "unloaded"


@dataclass
class PluginManifest:
    """Plugin metadata manifest."""

    name: str
    version: str
    type: PluginType
    description: str
    author: str
    compatible_versions: str = ">=0.1.0"
    dependencies: List[str] = field(default_factory=list)
    entry_point: str = ""
    config_schema: Dict = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


class PhantomPlugin(ABC):
    """
    Abstract base class for all phantom-scan plugins.

    Every plugin must implement these methods to be compatible
    with the plugin manager.
    """

    @property
    @abstractmethod
    def manifest(self) -> PluginManifest:
        """Return the plugin manifest with metadata."""
        pass

    @abstractmethod
    def load(self) -> bool:
        """
        Load the plugin resources.
        Returns True if loading succeeded.
        """
        pass

    @abstractmethod
    def initialize(self, config: Dict) -> bool:
        """
        Initialize the plugin with configuration.
        Returns True if initialization succeeded.
        """
        pass

    @abstractmethod
    def execute(self, *args, **kwargs) -> Optional[Dict]:
        """
        Execute the plugin's main functionality.
        Returns result dictionary or None.
        """
        pass

    @abstractmethod
    def unload(self) -> bool:
        """
        Unload the plugin and release resources.
        Returns True if unloading succeeded.
        """
        pass

    def get_status(self) -> PluginState:
        """Get current plugin state."""
        return self._state

    def _set_state(self, state: PluginState):
        """Internal method to update plugin state."""
        self._state = state


class ScannerPlugin(PhantomPlugin):
    """Base class for custom scanner plugins."""

    @abstractmethod
    def scan(self, target: str, options: Dict) -> Dict:
        """Execute custom scan logic."""
        pass


class FingerprintPlugin(PhantomPlugin):
    """Base class for custom service fingerprint plugins."""

    @abstractmethod
    def fingerprint(self, packet_data: bytes, port: int) -> Optional[Dict]:
        """Analyze packet data and return service fingerprint."""
        pass


class ExploitPlugin(PhantomPlugin):
    """Base class for custom exploit plugins."""

    @abstractmethod
    def check_vulnerability(self, target: str, port: int, service: str) -> Dict:
        """Check if target is vulnerable."""
        pass

    @abstractmethod
    def exploit(self, target: str, port: int, payload: Dict) -> Dict:
        """Execute exploit against target."""
        pass


class PayloadPlugin(PhantomPlugin):
    """Base class for custom payload generator plugins."""

    @abstractmethod
    def generate(self, payload_type: str, params: Dict) -> bytes:
        """Generate payload bytes."""
        pass


class OutputPlugin(PhantomPlugin):
    """Base class for custom output/report formatters."""

    @abstractmethod
    def format_report(self, data: Dict) -> str:
        """Format scan results into custom output."""
        pass

    @abstractmethod
    def save_report(self, data: Dict, output_path: str) -> bool:
        """Save formatted report to file."""
        pass


class PostModule(PhantomPlugin):
    """Base class for post-exploitation modules."""

    @abstractmethod
    def enumerate(self, session: Dict) -> Dict:
        """Enumerate targets from active session."""
        pass

    @abstractmethod
    def pivot(self, session: Dict, target: str) -> bool:
        """Establish pivot through compromised session."""
        pass
