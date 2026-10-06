"""py-netprobe - Single-command network diagnostic engine for Python."""

from .exceptions import (
    NetProbeException,
    DnsResolutionError,
    TcpConnectionError,
    TlsHandshakeError,
    HttpProtocolError,
)
from .models import ProbeReport, StageResult
from .sync_probe import probe
from .async_probe import probe_async

__version__ = "0.1.0"
__all__ = [
    "probe",
    "probe_async",
    "ProbeReport",
    "StageResult",
    "NetProbeException",
    "DnsResolutionError",
    "TcpConnectionError",
    "TlsHandshakeError",
    "HttpProtocolError",
]
