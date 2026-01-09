# aetherium_qcom/core/transport.py
"""
Pluggable Transport (PT) system for network obfuscation.

This module provides an interface for different transport methods to discover
public addresses and send/receive P2P communication in an obfuscated manner.
"""

from abc import ABC, abstractmethod
from typing import Optional, Tuple, Dict, Any
import asyncio
import os
import json
import base64
import urllib.request
import urllib.parse
import urllib.error
import random

try:
    import stun
except ImportError:
    stun = None


class PluggableTransport(ABC):
    """
    Abstract base class for pluggable transports.
    
    A pluggable transport provides two main capabilities:
    1. Discovery: Discovering the client's public IP and port
    2. Communication: Sending and receiving obfuscated P2P data
    """
    
    @abstractmethod
    async def discover_public_address(self, local_port: int) -> Tuple[Optional[str], Optional[int], Optional[str]]:
        """
        Discover the public IP address and port.
        
        Args:
            local_port: The local port to use for discovery
            
        Returns:
            Tuple of (public_ip, public_port, method_type) or (None, None, None) on failure
        """
        pass
    
    @abstractmethod
    def get_handshake_bytes(self) -> bytes:
        """
        Get the handshake bytes for this transport.
        
        Returns:
            Initial handshake bytes to send
        """
        pass
    
    @abstractmethod
    def verify_handshake(self, data: bytes) -> bool:
        """
        Verify that received data is a valid handshake for this transport.
        
        Args:
            data: Received handshake data
            
        Returns:
            True if valid handshake, False otherwise
        """
        pass
    
    @abstractmethod
    async def wrap_outgoing_data(self, data: bytes) -> bytes:
        """
        Wrap outgoing data in the transport's obfuscation format.
        
        Args:
            data: Plain encrypted payload to wrap
            
        Returns:
            Obfuscated data ready to send
        """
        pass
    
    @abstractmethod
    async def unwrap_incoming_data(self, data: bytes) -> Optional[bytes]:
        """
        Unwrap incoming obfuscated data to extract the payload.
        
        Args:
            data: Obfuscated data received
            
        Returns:
            Extracted encrypted payload, or None if invalid
        """
        pass
    
    @abstractmethod
    def get_transport_name(self) -> str:
        """Get the name of this transport."""
        pass
    
    @abstractmethod
    def get_transport_config(self) -> Dict[str, Any]:
        """
        Get the configuration for this transport to include in invitations.
        
        Returns:
            Dictionary with transport configuration
        """
        pass


class DefaultTransport(PluggableTransport):
    """
    Default transport using STUN for discovery and Fake-TLS for communication.
    
    This is the original implementation that mimics a TLS handshake.
    """
    
    # Default STUN servers (Google's public STUN servers)
    DEFAULT_STUN_SERVERS = [
        'stun.l.google.com:19302',
        'stun1.l.google.com:19302',
        'stun2.l.google.com:19302',
        'stun3.l.google.com:19302',
        'stun4.l.google.com:19302'
    ]
    
    TLS_HANDSHAKE = b'\x16\x03\x01'
    TLS_APPDATA = b'\x17\x03\x03'
    
    async def discover_public_address(self, local_port: int) -> Tuple[Optional[str], Optional[int], Optional[str]]:
        """Discover public address using STUN."""
        if stun is None:
            # STUN library not available - log warning
            # In production, this should use proper logging
            # print("Warning: pystun3 library not available. Public IP discovery will fail.")
            return None, None, "STUN Unavailable"
        
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()
        
        # Helper function to run the blocking STUN call in an executor
        async def get_stun_info(host, port):
            return await loop.run_in_executor(
                None,
                lambda: stun.get_ip_info(
                    source_port=local_port,
                    stun_host=host,
                    stun_port=port
                )
            )
        
        # Try default STUN servers
        for server in self.DEFAULT_STUN_SERVERS:
            stun_host, stun_port = server.split(':', 1)
            stun_port = int(stun_port)
            try:
                nat_type, external_ip, external_port = await get_stun_info(stun_host, stun_port)
                if external_ip and external_port:
                    return external_ip, external_port, f"STUN ({nat_type})"
            except Exception:
                continue
        
        return None, None, None
    
    def get_handshake_bytes(self) -> bytes:
        """Return TLS handshake bytes."""
        return self.TLS_HANDSHAKE + os.urandom(64)
    
    def verify_handshake(self, data: bytes) -> bool:
        """Verify TLS handshake format."""
        return data.startswith(self.TLS_HANDSHAKE)
    
    async def wrap_outgoing_data(self, data: bytes) -> bytes:
        """Wrap data with TLS application data header."""
        return self.TLS_APPDATA + len(data).to_bytes(4, 'big') + data
    
    async def unwrap_incoming_data(self, data: bytes) -> Optional[bytes]:
        """Extract payload from TLS application data format."""
        if not data.startswith(self.TLS_APPDATA):
            return None
        if len(data) < 7:  # 3 bytes header + 4 bytes length
            return None
        data_len = int.from_bytes(data[3:7], 'big')
        if len(data) < 7 + data_len:
            return None
        return data[7:7+data_len]
    
    def get_transport_name(self) -> str:
        return "default"
    
    def get_transport_config(self) -> Dict[str, Any]:
        return {"type": "default", "version": "1.0"}


class HTTPObfuscatedTransport(PluggableTransport):
    """
    HTTP-based obfuscated transport.
    
    - Discovery: Uses HTTP(S) requests to a decoy server to discover public IP
    - Communication: Wraps P2P data in HTTP POST/GET requests
    """
    
    # Default discovery endpoints (can be any HTTP service that returns the client's IP)
    DEFAULT_DISCOVERY_ENDPOINTS = [
        'https://api.ipify.org?format=json',
        'https://api.my-ip.io/ip.json',
        'https://ifconfig.me/all.json',
    ]
    
    # Common hosts to randomize for obfuscation
    COMMON_HOSTS = [
        'api.example.com',
        'cdn.cloudflare.com',
        'storage.googleapis.com',
        'api.github.com',
        'www.microsoft.com',
        's3.amazonaws.com',
    ]
    
    # Common user agents to randomize for obfuscation
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    ]
    
    def __init__(self, discovery_endpoint: Optional[str] = None):
        """
        Initialize HTTP obfuscated transport.
        
        Args:
            discovery_endpoint: Optional custom discovery endpoint URL
        """
        self.discovery_endpoint = discovery_endpoint
        # Pick random host and user agent for this session
        self.session_host = random.choice(self.COMMON_HOSTS)
        self.session_user_agent = random.choice(self.USER_AGENTS)
    
    async def discover_public_address(self, local_port: int) -> Tuple[Optional[str], Optional[int], Optional[str]]:
        """
        Discover public IP using HTTP(S) request.
        
        Note: This only discovers the IP, not the port. The port is assumed
        to be the same as the local_port (with potential NAT mapping).
        """
        endpoints = [self.discovery_endpoint] if self.discovery_endpoint else self.DEFAULT_DISCOVERY_ENDPOINTS
        
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = asyncio.get_event_loop()
        
        async def fetch_ip(url):
            """Fetch IP from endpoint."""
            try:
                req = urllib.request.Request(
                    url,
                    headers={
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                )
                response = await loop.run_in_executor(
                    None,
                    lambda: urllib.request.urlopen(req, timeout=5)
                )
                data = response.read().decode('utf-8')
                
                # Try to parse JSON response
                try:
                    json_data = json.loads(data)
                    # Look for common IP field names
                    for key in ['ip', 'IP', 'ipAddress', 'ip_addr', 'addr']:
                        if key in json_data:
                            return json_data[key]
                except json.JSONDecodeError:
                    # If not JSON, assume the response is just the IP
                    return data.strip()
                
                return None
            except Exception:
                return None
        
        # Try each endpoint
        for endpoint in endpoints:
            ip = await fetch_ip(endpoint)
            if ip:
                return ip, local_port, "HTTP Discovery"
        
        return None, None, None
    
    def get_handshake_bytes(self) -> bytes:
        """
        Return HTTP-like handshake bytes.
        
        Mimics an HTTP POST request with randomized host and user agent.
        """
        http_request = (
            f"POST /api/v1/connect HTTP/1.1\r\n"
            f"Host: {self.session_host}\r\n"
            f"User-Agent: {self.session_user_agent}\r\n"
            f"Content-Type: application/octet-stream\r\n"
            f"Content-Length: 32\r\n"
            f"\r\n"
        ).encode('ascii') + os.urandom(32)
        return http_request
    
    def verify_handshake(self, data: bytes) -> bool:
        """Verify HTTP handshake format."""
        return data.startswith(b"POST /api/v1/connect HTTP/1.1") or data.startswith(b"HTTP/1.1 200 OK")
    
    async def wrap_outgoing_data(self, data: bytes) -> bytes:
        """
        Wrap data as an HTTP POST request.
        
        The encrypted payload is sent as the POST body, encoded in base64
        to ensure it's HTTP-safe. Uses randomized host and user agent.
        """
        payload_b64 = base64.b64encode(data).decode('ascii')
        http_request = (
            f"POST /api/v1/data HTTP/1.1\r\n"
            f"Host: {self.session_host}\r\n"
            f"User-Agent: {self.session_user_agent}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(payload_b64) + 5}\r\n"  # +5 for "data="
            f"\r\n"
            f"data={payload_b64}"
        ).encode('ascii')
        return http_request
    
    async def unwrap_incoming_data(self, data: bytes) -> Optional[bytes]:
        """
        Extract payload from HTTP POST request format.
        """
        try:
            # Convert to string for parsing
            data_str = data.decode('ascii', errors='ignore')
            
            # Look for the body separator
            body_start = data_str.find('\r\n\r\n')
            if body_start == -1:
                return None
            
            body = data_str[body_start + 4:]
            
            # Extract base64 payload
            if body.startswith('data='):
                payload_b64 = body[5:]
                payload = base64.b64decode(payload_b64)
                return payload
            
            return None
        except Exception:
            return None
    
    def get_transport_name(self) -> str:
        return "http-obfuscated"
    
    def get_transport_config(self) -> Dict[str, Any]:
        config = {"type": "http-obfuscated", "version": "1.0"}
        if self.discovery_endpoint:
            config["discovery_endpoint"] = self.discovery_endpoint
        return config


class TransportFactory:
    """Factory for creating transport instances."""
    
    _transports = {
        "default": DefaultTransport,
        "http-obfuscated": HTTPObfuscatedTransport,
    }
    
    @classmethod
    def create_transport(cls, transport_type: str, config: Optional[Dict[str, Any]] = None) -> PluggableTransport:
        """
        Create a transport instance.
        
        Args:
            transport_type: Type of transport ("default", "http-obfuscated")
            config: Optional configuration dictionary
            
        Returns:
            Transport instance
            
        Raises:
            ValueError: If transport type is unknown
        """
        if transport_type not in cls._transports:
            raise ValueError(f"Unknown transport type: {transport_type}")
        
        transport_class = cls._transports[transport_type]
        
        if config is None:
            config = {}
        
        # Pass relevant config to constructor
        if transport_type == "http-obfuscated":
            return transport_class(discovery_endpoint=config.get("discovery_endpoint"))
        else:
            return transport_class()
    
    @classmethod
    def get_available_transports(cls) -> list:
        """Get list of available transport types."""
        return list(cls._transports.keys())
    
    @classmethod
    def register_transport(cls, name: str, transport_class: type):
        """
        Register a custom transport.
        
        Args:
            name: Name of the transport
            transport_class: Class implementing PluggableTransport
        """
        cls._transports[name] = transport_class
