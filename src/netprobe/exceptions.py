from __future__ import annotations

from typing import Optional


class NetProbeException(Exception):
    """Base exception for all netprobe diagnostic errors."""

    def __init__(self, message: str, stage: str, suggestion: Optional[str] = None):
        super().__init__(message)
        self.stage = stage
        self.suggestion = suggestion or "Verify network connectivity and destination parameters."


class DnsResolutionError(NetProbeException):
    """Raised when domain name resolution fails."""

    def __init__(self, host: str, original_error: str):
        super().__init__(
            f"DNS resolution failed for '{host}': {original_error}",
            stage="DNS",
            suggestion="Check local DNS server configuration, /etc/resolv.conf, or verify if the domain is registered.",
        )


class TcpConnectionError(NetProbeException):
    """Raised when TCP handshake cannot be established."""

    def __init__(self, ip: str, port: int, original_error: str):
        super().__init__(
            f"TCP handshake failed connecting to {ip}:{port}: {original_error}",
            stage="TCP",
            suggestion="Verify remote firewall rules, security groups, or check if the port is actively listening.",
        )


class TlsHandshakeError(NetProbeException):
    """Raised when TLS negotiation or certificate validation fails."""

    def __init__(self, host: str, port: int, original_error: str):
        super().__init__(
            f"TLS handshake failed connecting to {host}:{port}: {original_error}",
            stage="TLS",
            suggestion="Check if the SSL/TLS certificate is expired, self-signed, or if SNI host matches the certificate.",
        )


class HttpProtocolError(NetProbeException):
    """Raised when HTTP exchange fails or returns unexpected error status."""

    def __init__(self, status_code: int, reason: str):
        super().__init__(
            f"HTTP request returned server error {status_code} ({reason})",
            stage="HTTP",
            suggestion="Check remote web server/application logs for runtime crashes or misconfiguration.",
        )
