from __future__ import annotations

import socket
import ssl
import time
from urllib.parse import urlparse
from typing import Optional

from .exceptions import (
    DnsResolutionError,
    TcpConnectionError,
    TlsHandshakeError,
    HttpProtocolError,
)
from .models import ProbeReport, StageResult


def parse_target(target: str) -> tuple[str, int, str, bool]:
    """Parse input target (URL or host[:port]) into (host, port, path, is_tls)."""
    raw = target.strip()
    if not raw.startswith("http://") and not raw.startswith("https://"):
        if ":443" in raw or raw.endswith(".com") or raw.endswith(".org") or raw.endswith(".io") or raw.endswith(".dev"):
            raw = "https://" + raw
        else:
            raw = "http://" + raw

    parsed = urlparse(raw)
    is_tls = parsed.scheme == "https"
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if is_tls else 80)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query

    return host, port, path, is_tls


def probe(
    target: str,
    timeout: float = 10.0,
    insecure: bool = False,
    raise_for_status: bool = False,
) -> ProbeReport:
    """Run synchronous step-by-step network diagnostic probe."""
    host, port, path, is_tls = parse_target(target)
    stages: list[StageResult] = []
    resolved_ips: list[str] = []
    total_start = time.perf_counter()

    # --- 1. DNS Resolution ---
    dns_start = time.perf_counter()
    try:
        addr_info = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
        dns_latency = (time.perf_counter() - dns_start) * 1000
        for entry in addr_info:
            ip = entry[4][0]
            if ip not in resolved_ips:
                resolved_ips.append(ip)

        stages.append(
            StageResult(
                stage="DNS",
                success=True,
                latency_ms=dns_latency,
                details={"ips": resolved_ips, "count": len(resolved_ips)},
            )
        )
    except Exception as err:
        dns_latency = (time.perf_counter() - dns_start) * 1000
        err_msg = str(err)
        exc = DnsResolutionError(host, err_msg)
        stages.append(
            StageResult(
                stage="DNS",
                success=False,
                latency_ms=dns_latency,
                error=err_msg,
                suggestion=exc.suggestion,
            )
        )
        total_latency = (time.perf_counter() - total_start) * 1000
        report = ProbeReport(
            target=target,
            host=host,
            port=port,
            is_tls=is_tls,
            success=False,
            total_latency_ms=total_latency,
            resolved_ips=[],
            stages=stages,
            failure_stage="DNS",
            root_cause=str(exc),
        )
        if raise_for_status:
            raise exc
        return report

    # --- 2. TCP Handshake ---
    target_ip = resolved_ips[0]
    tcp_start = time.perf_counter()
    sock: Optional[socket.socket] = None
    try:
        sock = socket.create_connection((target_ip, port), timeout=timeout)
        tcp_latency = (time.perf_counter() - tcp_start) * 1000
        stages.append(
            StageResult(
                stage="TCP",
                success=True,
                latency_ms=tcp_latency,
                details={"connected_ip": target_ip, "port": port},
            )
        )
    except Exception as err:
        tcp_latency = (time.perf_counter() - tcp_start) * 1000
        err_msg = str(err)
        exc = TcpConnectionError(target_ip, port, err_msg)
        stages.append(
            StageResult(
                stage="TCP",
                success=False,
                latency_ms=tcp_latency,
                error=err_msg,
                suggestion=exc.suggestion,
            )
        )
        total_latency = (time.perf_counter() - total_start) * 1000
        report = ProbeReport(
            target=target,
            host=host,
            port=port,
            is_tls=is_tls,
            success=False,
            total_latency_ms=total_latency,
            resolved_ips=resolved_ips,
            stages=stages,
            failure_stage="TCP",
            root_cause=str(exc),
        )
        if raise_for_status:
            raise exc
        return report

    # --- 3. TLS Handshake (if applicable) ---
    active_sock = sock
    if is_tls:
        tls_start = time.perf_counter()
        try:
            ctx = ssl.create_default_context()
            if insecure:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

            tls_sock = ctx.wrap_socket(sock, server_hostname=host)
            tls_latency = (time.perf_counter() - tls_start) * 1000
            cipher = tls_sock.cipher()
            version = tls_sock.version()
            stages.append(
                StageResult(
                    stage="TLS",
                    success=True,
                    latency_ms=tls_latency,
                    details={
                        "version": version,
                        "cipher": cipher[0] if cipher else "unknown",
                    },
                )
            )
            active_sock = tls_sock
        except Exception as err:
            tls_latency = (time.perf_counter() - tls_start) * 1000
            err_msg = str(err)
            exc = TlsHandshakeError(host, port, err_msg)
            stages.append(
                StageResult(
                    stage="TLS",
                    success=False,
                    latency_ms=tls_latency,
                    error=err_msg,
                    suggestion=exc.suggestion,
                )
            )
            try:
                sock.close()
            except Exception:
                pass
            total_latency = (time.perf_counter() - total_start) * 1000
            report = ProbeReport(
                target=target,
                host=host,
                port=port,
                is_tls=is_tls,
                success=False,
                total_latency_ms=total_latency,
                resolved_ips=resolved_ips,
                stages=stages,
                failure_stage="TLS",
                root_cause=str(exc),
            )
            if raise_for_status:
                raise exc
            return report

    # --- 4. HTTP Exchange ---
    http_start = time.perf_counter()
    try:
        req_bytes = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: py-netprobe/0.1.0\r\nConnection: close\r\n\r\n".encode("utf-8")
        active_sock.sendall(req_bytes)
        response_header = b""
        while b"\r\n\r\n" not in response_header and b"\n\n" not in response_header:
            chunk = active_sock.recv(4096)
            if not chunk:
                break
            response_header += chunk

        http_latency = (time.perf_counter() - http_start) * 1000
        header_text = response_header.decode("utf-8", errors="replace")
        status_line = header_text.splitlines()[0] if header_text else "HTTP/1.1 200 OK"
        parts = status_line.split(" ", 2)
        status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 200
        reason = parts[2] if len(parts) >= 3 else "OK"

        stages.append(
            StageResult(
                stage="HTTP",
                success=status_code < 500,
                latency_ms=http_latency,
                details={"status": status_code, "reason": reason},
            )
        )
    except Exception as err:
        http_latency = (time.perf_counter() - http_start) * 1000
        err_msg = str(err)
        stages.append(
            StageResult(
                stage="HTTP",
                success=False,
                latency_ms=http_latency,
                error=err_msg,
                suggestion="Server prematurely closed connection or request timed out.",
            )
        )
    finally:
        try:
            active_sock.close()
        except Exception:
            pass

    total_latency = (time.perf_counter() - total_start) * 1000
    all_success = all(s.success for s in stages)
    failed_stage = next((s for s in stages if not s.success), None)

    report = ProbeReport(
        target=target,
        host=host,
        port=port,
        is_tls=is_tls,
        success=all_success,
        total_latency_ms=total_latency,
        resolved_ips=resolved_ips,
        stages=stages,
        failure_stage=failed_stage.stage if failed_stage else None,
        root_cause=failed_stage.error if failed_stage else None,
    )

    if raise_for_status and not all_success:
        raise HttpProtocolError(500, failed_stage.error or "HTTP stage failure")

    return report
