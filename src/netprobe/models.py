from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class StageResult:
    stage: str
    success: bool
    latency_ms: float
    details: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    suggestion: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "stage": self.stage,
            "success": self.success,
            "latency_ms": round(self.latency_ms, 2),
        }
        if self.details:
            d["details"] = self.details
        if self.error:
            d["error"] = self.error
        if self.suggestion:
            d["suggestion"] = self.suggestion
        return d


@dataclass
class ProbeReport:
    target: str
    host: str
    port: int
    is_tls: bool
    success: bool
    total_latency_ms: float
    resolved_ips: List[str]
    stages: List[StageResult]
    failure_stage: Optional[str] = None
    root_cause: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "is_tls": self.is_tls,
            "success": self.success,
            "total_latency_ms": round(self.total_latency_ms, 2),
            "resolved_ips": self.resolved_ips,
            "failure_stage": self.failure_stage,
            "root_cause": self.root_cause,
            "stages": [s.to_dict() for s in self.stages],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def format_waterfall(self) -> str:
        lines = [
            f"\nNetwork Diagnostic Report: {self.target}",
            "=" * 65,
            f"Host: {self.host}:{self.port} | TLS: {'Yes' if self.is_tls else 'No'}",
            f"Resolved IPs: {', '.join(self.resolved_ips) if self.resolved_ips else 'None'}",
            "-" * 65,
            f"{'STAGE':<8} {'STATUS':<10} {'LATENCY':<12} {'DETAILS'}",
            "-" * 65,
        ]

        for s in self.stages:
            status = "PASS" if s.success else "FAIL"
            lat_str = f"{s.latency_ms:.2f} ms"
            det_parts = []
            for k, v in s.details.items():
                det_parts.append(f"{k}={v}")
            if s.error:
                det_parts.append(f"err: {s.error}")
            details_str = " | ".join(det_parts)
            lines.append(f"{s.stage:<8} {status:<10} {lat_str:<12} {details_str}")

        lines.append("=" * 65)
        if self.success:
            lines.append(f"✔ All stages passed! Total latency: {self.total_latency_ms:.2f} ms\n")
        else:
            lines.append(f"✖ Diagnostic Failure in {self.failure_stage} stage!")
            if self.root_cause:
                lines.append(f"  Root Cause: {self.root_cause}")
            # Find suggestion
            failed_stage = next((s for s in self.stages if not s.success), None)
            if failed_stage and failed_stage.suggestion:
                lines.append(f"  Recommendation: {failed_stage.suggestion}\n")

        return "\n".join(lines)
