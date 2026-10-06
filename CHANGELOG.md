# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-10-06

### Added
- Initial public release of `py-netprobe`.
- Step-by-step diagnostic pipeline testing DNS resolution, TCP handshake, TLS negotiation, and HTTP exchange.
- High-precision latency waterfalls per stage.
- Root-cause diagnostic error analyzer with actionable exceptions:
  - `DnsResolutionError`
  - `TcpConnectionError`
  - `TlsHandshakeError`
  - `HttpProtocolError`
- Dual synchronous (`probe`) and asynchronous (`probe_async`) APIs.
- CLI tool `netprobe` with formatted waterfall tables and structured JSON export.
