import asyncio
import http.server
import json
import socket
import threading
import pytest

from netprobe import (
    probe,
    probe_async,
    DnsResolutionError,
    TcpConnectionError,
)
from netprobe.sync_probe import parse_target
from netprobe.cli import main as cli_main


class DummyHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"pong")

    def log_message(self, format, *args):
        pass  # Suppress logging


@pytest.fixture(scope="module")
def local_http_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), DummyHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}/health"
    server.shutdown()
    server.server_close()


def test_parse_target():
    h, p, path, tls = parse_target("example.com")
    assert h == "example.com"
    assert p == 443
    assert tls is True

    h, p, path, tls = parse_target("http://localhost:3000/api")
    assert h == "localhost"
    assert p == 3000
    assert path == "/api"
    assert tls is False


def test_failed_dns_resolution():
    report = probe("non-existent-domain-xyz-987654321.invalid", timeout=1.0)
    assert report.success is False
    assert report.failure_stage == "DNS"
    assert "DNS" in report.format_waterfall()

    with pytest.raises(DnsResolutionError):
        probe("non-existent-domain-xyz-987654321.invalid", timeout=1.0, raise_for_status=True)


def test_failed_tcp_connection():
    # Pick a random unused port on localhost
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()

    report = probe(f"http://127.0.0.1:{port}", timeout=1.0)
    assert report.success is False
    assert report.failure_stage == "TCP"

    with pytest.raises(TcpConnectionError):
        probe(f"http://127.0.0.1:{port}", timeout=1.0, raise_for_status=True)


def test_successful_sync_probe(local_http_server):
    report = probe(local_http_server, timeout=2.0)
    assert report.success is True
    assert report.failure_stage is None
    assert len(report.stages) >= 3  # DNS, TCP, HTTP
    assert report.total_latency_ms > 0

    waterfall = report.format_waterfall()
    assert "DNS" in waterfall
    assert "TCP" in waterfall
    assert "HTTP" in waterfall
    assert "PASS" in waterfall


def test_successful_async_probe(local_http_server):
    async def _run():
        report = await probe_async(local_http_server, timeout=2.0)
        assert report.success is True
        assert report.failure_stage is None
        assert len(report.stages) >= 3

    asyncio.run(_run())


def test_cli_execution(local_http_server, capsys):
    ret = cli_main([local_http_server, "--json"])
    assert ret == 0

    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["success"] is True
    assert "stages" in data
