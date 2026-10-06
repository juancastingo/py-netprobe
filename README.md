# py-netprobe

[![CI](https://github.com/juancastingo/py-netprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/juancastingo/py-netprobe/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/py-netprobe.svg)](https://pypi.org/project/py-netprobe/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)

**py-netprobe** is a single-command network and TLS diagnostic engine for Python. It probes the complete connection lifecycle — **DNS $\rightarrow$ TCP $\rightarrow$ TLS $\rightarrow$ HTTP** — isolating exactly where connectivity breaks down and measuring latency waterfalls at every step.

---

## Features

- 🔬 **Granular Pipeline Breakdown**: Dissects network requests into distinct measurable phases:
  - **DNS**: Resolution latency, IPv4/IPv6 addresses discovered.
  - **TCP**: 3-way handshake round-trip time, firewall connection timeouts.
  - **TLS**: SSL handshake latency, cipher suite, protocol version, and certificate validation.
  - **HTTP**: Request/response round-trip and status codes.
- 🚨 **Diagnostic Exceptions**: Translates network errors into actionable root-cause exceptions:
  - `DnsResolutionError`: Misconfigured DNS / NXDOMAIN.
  - `TcpConnectionError`: Remote port closed, firewall dropped, or host unreachable.
  - `TlsHandshakeError`: Expired cert, SNI mismatch, untrusted authority.
  - `HttpProtocolError`: Remote server errors (HTTP 5xx).
- ⚡ **Sync + Async**: First-class synchronous (`probe`) and `asyncio` (`probe_async`) APIs.
- 📦 **Zero External Dependencies**: Pure Python 3.9+ standard library.

---

## Installation

```bash
pip install py-netprobe
```

---

## Python API Usage

### Synchronous Network Diagnostics

```python
from netprobe import probe, DnsResolutionError, TcpConnectionError

try:
    report = probe("https://api.github.com", timeout=5.0)
    print(report.format_waterfall())
except DnsResolutionError as e:
    print(f"DNS failure: {e}. Suggestion: {e.suggestion}")
except TcpConnectionError as e:
    print(f"TCP failure: {e}. Suggestion: {e.suggestion}")
```

### Asyncio Support

```python
import asyncio
from netprobe import probe_async

async def main():
    report = await probe_async("https://api.stripe.com")
    print(f"Resolved IPs: {report.resolved_ips}")
    print(f"Total Latency: {report.total_latency_ms:.2f} ms")
    for stage in report.stages:
        print(f"  [{stage.stage}] {stage.latency_ms:.2f} ms ({stage.details})")

asyncio.run(main())
```

---

## CLI Usage

### Diagnose Any URL or Host

```bash
netprobe https://github.com
```

Output:
```text
Network Diagnostic Report: https://github.com
=================================================================
Host: github.com:443 | TLS: Yes
Resolved IPs: 140.82.112.4
-----------------------------------------------------------------
STAGE    STATUS     LATENCY      DETAILS
-----------------------------------------------------------------
DNS      PASS       12.40 ms     ips=['140.82.112.4'] | count=1
TCP      PASS       24.15 ms     connected_ip=140.82.112.4 | port=443
TLS      PASS       45.80 ms     version=TLSv1.3 | cipher=TLS_AES_128_GCM_SHA256
HTTP     PASS       52.10 ms     status=200 | reason=OK
=================================================================
✔ All stages passed! Total latency: 134.45 ms
```

### JSON Export for CI/CD

```bash
netprobe https://api.myservice.internal --json
```

---

## License

MIT License © 2026 Juan Castin
