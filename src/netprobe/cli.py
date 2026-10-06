from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from .sync_probe import probe


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netprobe",
        description="Single-command network diagnostic engine testing DNS -> TCP -> TLS -> HTTP with latency waterfall",
    )
    parser.add_argument(
        "target",
        help="Target domain, IP, or URL to probe (e.g. google.com, https://api.github.com)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output diagnostics in structured JSON format",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Socket and stage timeout in seconds (default: 10.0)",
    )
    parser.add_argument(
        "--insecure",
        "-k",
        action="store_true",
        help="Skip TLS certificate verification",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version="netprobe 0.1.0",
    )
    return parser


def main(args: Optional[List[str]] = None) -> int:
    parser = create_parser()
    parsed = parser.parse_args(args)

    try:
        report = probe(
            target=parsed.target,
            timeout=parsed.timeout,
            insecure=parsed.insecure,
        )

        if parsed.json:
            print(report.to_json())
        else:
            print(report.format_waterfall())

        return 0 if report.success else 1
    except Exception as err:
        sys.stderr.write(f"Diagnostic execution error: {err}\n")
        return 2


if __name__ == "__main__":
    sys.exit(main())
