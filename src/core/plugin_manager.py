"""
phantom-scan — Plugin Manager
=================================
Central plugin management system for phantom-scan.

Handles:
1. Dynamic discovery and loading of plugins from directories
2. Dependency resolution between plugins
3. Plugin lifecycle management
4. Version compatibility checking
5. Plugin registry and lookup
6. Community signature library management

Plugins are loaded from:
- Built-in plugins in src/plugins/
- User plugins in ~/.phantom-scan/plugins/
- Community plugins from configured repositories
"""

import importlib
import importlib.util
import logging
import os
import sys
from typing import Optional, List, Dict, Type
from pathlib import Path
from datetime import datetime

from src.core.plugin_base import (
    PhantomPlugin,
    PluginManifest,
    PluginType,
    PluginState,
    ScannerPlugin,
    FingerprintPlugin,
    ExploitPlugin,
    PayloadPlugin,
    OutputPlugin,
    PostModule,
)

logger = logging.getLogger("phantom-scan")


class PluginManager:
    """
    Central plugin management system.

    Manages the complete lifecycle of all plugins:
    discovery → loading → initialization → execution → unloading
    """

    def __init__(self):
        self.plugins: Dict[str, PhantomPlugin] = {}
        self.manifests: Dict[str, PluginManifest] = {}
        self.plugin_dirs: List[str] = [
            str(Path(__file__).parent.parent / "plugins"),
            str(Path.home() / ".phantom-scan" / "plugins"),
        ]
        self.loaded_files: Dict[str, str] = {}
        self.load_history: List[Dict] = []

    def discover_plugins(self) -> List[str]:
        """
        Discover all available plugins from configured directories.

        Returns:
            List of plugin names found
        """
        discovered = []

        for plugin_dir in self.plugin_dirs:
            dir_path = Path(plugin_dir)
            if not dir_path.exists():
                continue

            for plugin_file in dir_path.glob("*.py"):
                if plugin_file.name.startswith("_"):
                    continue
                plugin_name = plugin_file.stem
                if plugin_name not in self.plugins:
                    discovered.append(plugin_name)
                    logger.info(f"[PLUGIN] Discovered: {plugin_name} from {plugin_dir}")

        return discovered

    def load_plugin(self, plugin_path: str) -> bool:
        """
        Load a plugin from a file path.

        Args:
            plugin_path: Absolute path to plugin Python file

        Returns:
            True if loaded successfully
        """
        try:
            spec = importlib.util.spec_from_file_location("phantom_plugin", plugin_path)
            if spec is None or spec.loader is None:
                logger.error(f"[PLUGIN] Cannot load {plugin_path}: invalid spec")
                return False

            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)

            # Look for plugin class in module
            plugin_class = self._find_plugin_class(module)
            if not plugin_class:
                logger.error(f"[PLUGIN] No PhantomPlugin subclass found in {plugin_path}")
                return False

            instance = plugin_class()
            self.plugins[instance.manifest.name] = instance
            self.manifests[instance.manifest.name] = instance.manifest
            self.loaded_files[instance.manifest.name] = plugin_path
            instance._set_state(PluginState.LOADED)

            self.load_history.append(
                {
                    "plugin": instance.manifest.name,
                    "action": "loaded",
                    "timestamp": datetime.now().isoformat(),
                    "path": plugin_path,
                }
            )

            logger.info(
                f"[PLUGIN] Loaded {instance.manifest.name} v{instance.manifest.version} "
                f"({instance.manifest.type.value})"
            )
            return True

        except Exception as e:
            logger.error(f"[PLUGIN] Failed to load {plugin_path}: {e}")
            return False

    def load_builtin_plugins(self) -> int:
        """
        Load all built-in plugins from src/plugins/ directory.

        Returns:
            Number of plugins loaded
        """
        built_in_dir = Path(__file__).parent.parent / "plugins"
        count = 0

        if built_in_dir.exists():
            for plugin_file in built_in_dir.glob("*.py"):
                if plugin_file.name.startswith("_"):
                    continue
                if self.load_plugin(str(plugin_file)):
                    count += 1

        logger.info(f"[PLUGIN] Loaded {count} built-in plugins")
        return count

    def initialize_plugin(self, plugin_name: str, config: Dict = None) -> bool:
        """
        Initialize a loaded plugin with configuration.

        Args:
            plugin_name: Name of the plugin
            config: Configuration dictionary

        Returns:
            True if initialization succeeded
        """
        if plugin_name not in self.plugins:
            logger.error(f"[PLUGIN] {plugin_name} not loaded")
            return False

        plugin = self.plugins[plugin_name]
        try:
            if plugin.initialize(config or {}):
                plugin._set_state(PluginState.INITIALIZED)
                logger.info(f"[PLUGIN] {plugin_name} initialized")
                return True
            else:
                plugin._set_state(PluginState.ERROR)
                return False
        except Exception as e:
            logger.error(f"[PLUGIN] Init error for {plugin_name}: {e}")
            plugin._set_state(PluginState.ERROR)
            return False

    def initialize_all(self, config: Dict = None) -> int:
        """Initialize all loaded plugins."""
        count = 0
        for name in self.plugins:
            if self.initialize_plugin(name, config):
                count += 1
        return count

    def execute_plugin(self, plugin_name: str, *args, **kwargs) -> Optional[Dict]:
        """
        Execute a loaded plugin.

        Args:
            plugin_name: Name of the plugin
            *args, **kwargs: Arguments passed to plugin.execute()

        Returns:
            Plugin execution result or None
        """
        if plugin_name not in self.plugins:
            logger.error(f"[PLUGIN] {plugin_name} not loaded")
            return None

        plugin = self.plugins[plugin_name]
        if plugin.get_state() not in [PluginState.INITIALIZED, PluginState.ACTIVE]:
            logger.warning(f"[PLUGIN] {plugin_name} not initialized (state: {plugin.get_state()})")
            return None

        try:
            plugin._set_state(PluginState.ACTIVE)
            result = plugin.execute(*args, **kwargs)
            plugin._set_state(PluginState.INITIALIZED)
            return result
        except Exception as e:
            logger.error(f"[PLUGIN] Execution error for {plugin_name}: {e}")
            plugin._set_state(PluginState.ERROR)
            return None

    def unload_plugin(self, plugin_name: str) -> bool:
        """
        Unload a plugin and release resources.

        Args:
            plugin_name: Name of the plugin

        Returns:
            True if unloaded successfully
        """
        if plugin_name not in self.plugins:
            return False

        plugin = self.plugins[plugin_name]
        try:
            if plugin.unload():
                plugin._set_state(PluginState.UNLOADED)
                del self.plugins[plugin_name]
                del self.manifests[plugin_name]
                logger.info(f"[PLUGIN] Unloaded {plugin_name}")
                return True
        except Exception as e:
            logger.error(f"[PLUGIN] Unload error for {plugin_name}: {e}")
            plugin._set_state(PluginState.ERROR)
            return False

    def unload_all(self) -> int:
        """Unload all plugins."""
        count = 0
        for name in list(self.plugins.keys()):
            if self.unload_plugin(name):
                count += 1
        return count

    def get_plugin(self, plugin_name: str) -> Optional[PhantomPlugin]:
        """Get a loaded plugin by name."""
        return self.plugins.get(plugin_name)

    def get_plugins_by_type(self, plugin_type: PluginType) -> List[PhantomPlugin]:
        """Get all plugins of a specific type."""
        return [p for p in self.plugins.values() if p.manifest.type == plugin_type]

    def get_plugin_report(self) -> Dict:
        """Generate plugin management report."""
        return {
            "total_plugins": len(self.plugins),
            "plugins": {
                name: {
                    "manifest": (
                        self.manifests[name].to_dict()
                        if hasattr(self.manifests[name], "to_dict")
                        else vars(self.manifests[name])
                    ),
                    "state": self.plugins[name].get_state().value,
                }
                for name in self.plugins
            },
            "load_history": self.load_history[-20:],  # Last 20 entries
        }

    def _find_plugin_class(self, module) -> Optional[Type[PhantomPlugin]]:
        """Find PhantomPlugin subclass in module."""
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if isinstance(attr, type) and issubclass(attr, PhantomPlugin) and attr != PhantomPlugin:
                return attr
        return None

    def get_load_history(self) -> List[Dict]:
        """Get plugin load history."""
        return self.load_history


class SignatureLibrary:
    """
    Community signature library for shared fingerprints, exploits, and payloads.

    Manages community-contributed security signatures that can be
    imported and used across installations.
    """

    def __init__(self, plugin_manager: PluginManager):
        self.plugin_manager = plugin_manager
        self.signatures: Dict[str, Dict] = {}
        self.community_url = "https://raw.githubusercontent.com/phantom-scan/signatures/main/"

    def load_signatures(self, source: str = "community") -> int:
        """
        Load signatures from community source.

        Args:
            source: Source identifier ('community', 'local', or URL)

        Returns:
            Number of signatures loaded
        """
        count = 0

        if source == "community":
            # Load from community plugins
            plugins = self.plugin_manager.get_plugins_by_type(PluginType.FINGERPRINT)
            for plugin in plugins:
                manifest = plugin.manifest
                self.signatures[manifest.name] = {
                    "type": "fingerprint",
                    "version": manifest.version,
                    "author": manifest.author,
                    "description": manifest.description,
                }
                count += 1

            plugins = self.plugin_manager.get_plugins_by_type(PluginType.EXPLOIT)
            for plugin in plugins:
                manifest = plugin.manifest
                self.signatures[manifest.name] = {
                    "type": "exploit",
                    "version": manifest.version,
                    "author": manifest.author,
                    "description": manifest.description,
                }
                count += 1

        logger.info(f"[SIGNATURES] Loaded {count} signatures from {source}")
        return count

    def add_signature(self, name: str, signature: Dict) -> bool:
        """Add a custom signature to the library."""
        self.signatures[name] = signature
        logger.info(f"[SIGNATURES] Added signature: {name}")
        return True

    def get_signature(self, name: str) -> Optional[Dict]:
        """Get a signature by name."""
        return self.signatures.get(name)

    def get_signatures_by_type(self, sig_type: str) -> List[Dict]:
        """Get all signatures of a specific type."""
        return [s for s in self.signatures.values() if s.get("type") == sig_type]

    def get_library_report(self) -> Dict:
        """Generate signature library report."""
        return {
            "total_signatures": len(self.signatures),
            "by_type": {
                sig_type: len([s for s in self.signatures.values() if s.get("type") == sig_type])
                for sig_type in set(s.get("type") for s in self.signatures.values())
            },
            "signatures": self.signatures,
        }
