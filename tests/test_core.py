import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.config import Config
from src.core.timing import AdaptiveTimer, TimingProfile
from src.core.fingerprint_engine import ServiceFingerprinter, ServiceFingerprint, ResponseSignature
from src.core.protocol_state import ProtocolStateAnalyzer, ProtocolState
from src.core.payload_engine import PayloadEngine, PayloadConfig, GeneratedPayload
from src.core.exploitation_engine import ExploitationEngine, ExploitationTarget
from src.core.network_graph import NetworkGraph, ProxyNode, ProxyChain
from src.core.proxy_chain import ProxyChainBuilder
from src.core.tunnel_manager import TunnelManager, TunnelConfig, TunnelState
from src.core.plugin_base import (
    PhantomPlugin,
    PluginManifest,
    PluginType,
    PluginState,
    ScannerPlugin,
    FingerprintPlugin,
    ExploitPlugin,
    PayloadPlugin,
)
from src.core.plugin_manager import PluginManager, SignatureLibrary
from src.plugins.community_signatures import (
    HTTP2Fingerprint,
    SSRFExploit,
    CustomDNSScanner,
    CustomEncodingPayload,
)
from src.modules.fingerprint import SERVICE_FINGERPRINTS, OS_FINGERPRINTS
from src.modules.exploit_db import ExploitDatabase, ExploitEntry, EXPLOIT_DATABASE
from scapy.all import IP, TCP, conf

conf.verb = 0


class TestConfig:
    def test_default_config(self):
        config = Config()
        assert config.target == "127.0.0.1"
        assert config.port_range == "1-1024"
        assert config.passive is False

    def test_port_parsing(self):
        config = Config(port_range="1-100")
        assert config.parsed_ports == (1, 100)

    def test_config_validation(self):
        config = Config(min_rtt_ms=5, max_jitter_ms=30)
        assert config.validate() is True


class TestTimingProfile:
    def test_interval_calculation(self):
        profile = TimingProfile(min_rtt_ms=5, max_jitter_ms=30)
        profile.update_rtt(20.0)
        interval = profile.calculate_next_interval()
        assert 0 < interval < 200

    def test_detection_risk_assessment(self):
        profile = TimingProfile()
        risk = profile.assess_detection_risk(200, 60)
        assert 0.0 <= risk <= 1.0


class TestAdaptiveTimer:
    def test_slowdown_adjustment(self):
        config = Config(min_rtt_ms=5, max_jitter_ms=30)
        timer = AdaptiveTimer(config)
        timer.record_response(50.0, 500, 2000)
        assert timer.slowdown_factor > 1.0

    def test_stats_reporting(self):
        config = Config(min_rtt_ms=5, max_jitter_ms=30)
        timer = AdaptiveTimer(config)
        timer.record_response(20.0, 0, 60)
        stats = timer.get_stats()
        assert "probe_count" in stats


class TestServiceFingerprinter:
    def test_fingerprint_port_ssh(self):
        fp = ServiceFingerprinter()
        sig = ResponseSignature()
        sig.window_size = 5760
        sig.ttl = 64
        sig.mss = 1460
        sig.wscale = 4
        sig.timestamp = True
        sig.sack_perm = True
        sig.options_order = "MSS,WScale,SAckOK,Timestamp"
        result = fp.fingerprint_port(sig, 22)
        assert result is not None

    def test_os_identification_linux(self):
        fp = ServiceFingerprinter()
        sig = ResponseSignature()
        sig.window_size = 5760
        sig.ttl = 64
        sig.df_flag = True
        sig.options_order = "MSS,WScale,SAckOK,Timestamp"
        assert fp._identify_os(sig) == "linux"

    def test_fingerprint_report(self):
        fp = ServiceFingerprinter()
        sig = ResponseSignature()
        sig.window_size = 8192
        sig.ttl = 64
        sig.mss = 1460
        sig.wscale = 7
        sig.timestamp = True
        sig.sack_perm = True
        sig.options_order = "MSS,NOP,WScale,NOP,NOP,SAckOK,Timestamp"
        fp.fingerprint_port(sig, 80)
        assert fp.get_fingerprint_report()["total_fingerprints"] >= 0


class TestProtocolStateAnalyzer:
    def test_syn_state_transition(self):
        analyzer = ProtocolStateAnalyzer()
        syn_packet = IP(dst="192.168.1.1") / TCP(dport=22, sport=12345, flags="S")
        analyzer.observe_packet(syn_packet)
        assert analyzer.get_service_state(22) == "SYN_SENT"

    def test_anomaly_detection(self):
        analyzer = ProtocolStateAnalyzer()
        for _ in range(60):
            packet = IP(dst="192.168.1.1") / TCP(dport=9999, sport=12345, flags="S")
            analyzer.observe_packet(packet)
        assert len(analyzer.get_anomalies()) > 0


class TestExploitDatabase:
    def test_known_cves_present(self):
        cve_ids = [e.cve_id for e in EXPLOIT_DATABASE]
        assert "CVE-2021-44228" in cve_ids
        assert "CVE-2017-0144" in cve_ids

    def test_service_lookup_alias(self):
        db = ExploitDatabase()
        assert len(db.lookup_by_service("smb")) > 0

    def test_critical_filter(self):
        db = ExploitDatabase()
        assert len(db.get_critical_exploits("smb", min_cvss=9.0)) > 0


class TestPayloadEngine:
    def test_xor_encoding_roundtrip(self):
        config = PayloadConfig(encoding="xor", encoding_key="testkey", append_random_padding=False)
        engine = PayloadEngine(config)
        payload = engine.generate_rce_payload("hello")
        assert payload.decode() == b"hello"

    def test_nopsled_generation(self):
        config = PayloadConfig(encoding="base64", append_random_padding=False)
        engine = PayloadEngine(config)
        assert len(engine.generate_nopsled(100)) == 100


class TestExploitationEngine:
    def test_analyze_scan_results(self):
        config = Config()
        engine = ExploitationEngine(config)
        scan_results = [
            {"port": 80, "state": "open", "fingerprint": {"service": "http", "os_hint": "linux"}},
            {"port": 445, "state": "open", "fingerprint": {"service": "smb", "os_hint": "windows"}},
        ]
        targets = engine.analyze_scan_results(scan_results)
        assert len(targets) > 0


class TestNetworkGraph:
    def test_shortest_path(self):
        graph = NetworkGraph()
        graph.add_node("A")
        graph.add_node("B")
        graph.add_node("C")
        graph.add_edge("A", "B", latency=5.0, reliability=0.9, risk=0.1)
        graph.add_edge("B", "C", latency=5.0, reliability=0.9, risk=0.1)
        graph.add_edge("A", "C", latency=100.0, reliability=0.5, risk=0.8)
        assert graph.shortest_path("A", "C") == ["A", "B", "C"]

    def test_no_path(self):
        graph = NetworkGraph()
        graph.add_node("A")
        graph.add_node("B")
        graph.add_edge("A", "B", latency=5.0, reliability=0.9, risk=0.1)
        assert graph.shortest_path("B", "C") is None


class TestProxyChainBuilder:
    def test_discover_nodes(self):
        builder = ProxyChainBuilder()
        scan_results = [
            {
                "port": 80,
                "state": "open",
                "target": "10.0.0.1",
                "fingerprint": {"service": "http", "os_hint": "linux"},
            },
            {
                "port": 22,
                "state": "open",
                "target": "10.0.0.2",
                "fingerprint": {"service": "ssh", "os_hint": "linux"},
            },
        ]
        nodes = builder.discover_nodes(scan_results)
        assert len(nodes) > 0


class TestTunnelManager:
    def test_tunnel_lifecycle(self):
        manager = TunnelManager()
        config = TunnelConfig(
            local_port=9091, remote_host="10.0.0.1", remote_port=80, proxy_chain=[]
        )
        tunnel_id = manager.create_tunnel(config)
        assert tunnel_id == 1
        stats = manager.get_tunnel_stats(tunnel_id)
        assert stats["local_port"] == 9091
        assert manager.close_tunnel(tunnel_id) is True

    def test_manager_summary(self):
        manager = TunnelManager()
        config = TunnelConfig(
            local_port=9092, remote_host="10.0.0.1", remote_port=80, proxy_chain=[]
        )
        manager.create_tunnel(config)
        summary = manager.get_manager_summary()
        assert summary["total_tunnels"] == 1


class TestPluginBase:
    def test_plugin_manifest(self):
        manifest = PluginManifest(
            name="test-plugin",
            version="1.0.0",
            type=PluginType.SCANNER,
            description="Test plugin",
            author="test",
        )
        assert manifest.name == "test-plugin"
        assert manifest.version == "1.0.0"
        assert manifest.type == PluginType.SCANNER

    def test_plugin_type_enum(self):
        assert PluginType.SCANNER.value == "scanner"
        assert PluginType.FINGERPRINT.value == "fingerprint"
        assert PluginType.EXPLOIT.value == "exploit"
        assert PluginType.PAYLOAD.value == "payload"
        assert PluginType.OUTPUT.value == "output"
        assert PluginType.POST_MODULE.value == "post_module"

    def test_plugin_state_enum(self):
        assert PluginState.LOADED.value == "loaded"
        assert PluginState.INITIALIZED.value == "initialized"
        assert PluginState.ACTIVE.value == "active"
        assert PluginState.ERROR.value == "error"
        assert PluginState.UNLOADED.value == "unloaded"


class TestPluginManager:
    def test_manager_initialization(self):
        manager = PluginManager()
        assert len(manager.plugins) == 0
        assert len(manager.manifests) == 0

    def test_discover_plugins(self):
        manager = PluginManager()
        # Built-in plugins dir exists
        discovered = manager.discover_plugins()
        # May find community_signatures or none
        assert isinstance(discovered, list)

    def test_plugin_manager_report(self):
        manager = PluginManager()
        report = manager.get_plugin_report()
        assert "total_plugins" in report
        assert isinstance(report["total_plugins"], int)

    def test_plugin_manager_load_history(self):
        manager = PluginManager()
        history = manager.get_load_history()
        assert isinstance(history, list)


class TestSignatureLibrary:
    def test_signature_library_initialization(self):
        manager = PluginManager()
        library = SignatureLibrary(manager)
        assert library.signatures == {}

    def test_add_and_get_signature(self):
        manager = PluginManager()
        library = SignatureLibrary(manager)
        library.add_signature("test-sig", {"type": "fingerprint", "name": "test"})
        assert library.get_signature("test-sig") is not None
        assert library.get_signature("test-sig")["type"] == "fingerprint"

    def test_signatures_by_type(self):
        manager = PluginManager()
        library = SignatureLibrary(manager)
        library.add_signature("sig1", {"type": "fingerprint"})
        library.add_signature("sig2", {"type": "exploit"})
        fps = library.get_signatures_by_type("fingerprint")
        assert len(fps) == 1

    def test_library_report(self):
        manager = PluginManager()
        library = SignatureLibrary(manager)
        library.add_signature("sig1", {"type": "fingerprint"})
        report = library.get_library_report()
        assert report["total_signatures"] == 1
        assert "by_type" in report


class TestCommunitySignatures:
    def test_http2_fingerprint_plugin(self):
        plugin = HTTP2Fingerprint()
        assert plugin.manifest.name == "http2-fingerprint"
        assert plugin.manifest.type == PluginType.FINGERPRINT
        assert plugin.load() is True
        assert plugin.initialize({}) is True

    def test_ssrf_exploit_plugin(self):
        plugin = SSRFExploit()
        assert plugin.manifest.name == "ssrf-exploit"
        assert plugin.manifest.type == PluginType.EXPLOIT
        assert plugin.load() is True
        assert plugin.initialize({}) is True

    def test_ssrf_check_vulnerability(self):
        plugin = SSRFExploit()
        plugin.load()
        plugin.initialize({})
        result = plugin.check_vulnerability("10.0.0.1", 80, "http")
        assert result["vulnerable"] is True
        assert result["cvss_score"] == 7.5

    def test_custom_dns_scanner(self):
        plugin = CustomDNSScanner()
        assert plugin.manifest.name == "dns-enumerator"
        assert plugin.manifest.type == PluginType.SCANNER
        assert plugin.load() is True
        result = plugin.scan("example.com", {})
        assert result["target"] == "example.com"

    def test_custom_encoding_payload(self):
        plugin = CustomEncodingPayload()
        assert plugin.manifest.name == "custom-encoding"
        assert plugin.manifest.type == PluginType.PAYLOAD
        assert plugin.load() is True
        data = plugin.generate("test", {"data": b"hello"})
        assert isinstance(data, bytes)


class TestFingerprintDatabase:
    def test_service_fingerprint_ports(self):
        for fp_data in SERVICE_FINGERPRINTS.values():
            if fp_data.get("port"):
                assert isinstance(fp_data["port"], int)
                assert fp_data["port"] > 0
