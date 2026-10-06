from __future__ import annotations

import asyncio
import ssl
import time
from typing import Optional

from .exceptions import (
    DnsResolutionError,
    TcpConnectionError,
    TlsHandshakeError,
)
from .models import ProbeReport, StageResult
from .sync_probe import parse_target


async def probe_async(
    target: str,
    timeout: float = 10.0,
    insecure: bool = False,
    raise_for_status: bool = False,
) -> ProbeReport:
    """Run asynchronous step-by-step network diagnostic probe using asyncio."""
    host, port, path, is_tls = parse_target(target)
    stages: list[StageResult] = []
    resolved_ips: list[str] = []
    loop = asyncio.get_running_loop()
    total_start = time.perf_counter()

    # 1. DNS Resolution
    dns_start = time.perf_counter()
    try:
        addr_info = await asyncio.wait_for(
            loop.getaddrinfo(host, port, proto=0),
            timeout=timeout,
        )
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

    # 2. TCP + TLS Handshake via asyncio.open_connection
    target_ip = resolved_ips[0]
    tcp_start = time.perf_counter()
    reader: Optional[asyncio.StreamReader] = None
    writer: Optional[asyncio.StreamWriter] = None

    try:
        # First test raw TCP
        _, raw_writer = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port),
            timeout=timeout,
        )
        tcp_latency = (time.perf_counter() - tcp_start) * 1000
        stages.append(
            StageResult(
                stage="TCP",
                success=True,
                latency_ms=tcp_latency,
                details={"connected_ip": target_ip, "port": port},
            )
        )
        raw_writer.close()
        await raw_writer.wait_closed()
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

    # Connect for HTTP exchange (with optional TLS)
    ssl_context = None
    if is_tls:
        tls_start = time.perf_counter()
        try:
            ssl_context = ssl.create_default_context()
            if insecure:
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port, ssl=ssl_context, server_hostname=host),
                timeout=timeout,
            )
            tls_latency = (time.perf_counter() - tls_start) * 1000
            stages.append(
                StageResult(
                    stage="TLS",
                    success=True,
                    latency_ms=tls_latency,
                    details={"server_hostname": host},
                )
            )
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
    else:
        reader, writer = await asyncio.open_connection(target_ip, port)

    # 3. HTTP Exchange
    http_start = time.perf_counter()
    try:
        req_text = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: py-netprobe/0.1.0\r\nConnection: close\r\n\r\n"
        writer.write(req_text.encode("utf-8"))
        await writer.drain()

        line_bytes = await asyncio.wait_for(reader.readline(), timeout=timeout)
        http_latency = (time.perf_counter() - http_start) * 1000

        line_str = line_bytes.decode("utf-8", errors="replace").strip()
        parts = line_str.split(" ", 2)
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
        stages.append(
            StageResult(
                stage="HTTP",
                success=False,
                latency_ms=http_latency,
                error=str(err),
            )
        )
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    total_latency = (time.perf_counter() - total_start) * 1000
    all_success = all(s.success for s in stages)
    failed_stage = next((s for s in stages if not s.success), None)

    return ProbeReport(
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
