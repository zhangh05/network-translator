"""Phase 8A: Batch validation orchestration and performance baseline."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from core.ir_models import IRConfig, IRConfigMeta
from core.renderer.base import RenderResult
from core.validator import CompositeValidator
from core.validator.base import ValidationReport
from core.vendor import get_profile, init_profiles


@dataclass
class BatchTask:
    """A single validation task specification."""
    name: str
    source_vendor: str
    target_vendor: str
    domain: str
    ir: IRConfig
    render_result: RenderResult
    target_config: str = "hostname Test\n"

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "source_vendor": self.source_vendor,
            "target_vendor": self.target_vendor,
            "domain": self.domain,
        }


@dataclass
class TaskResult:
    """Result of a single batch task execution."""
    task: BatchTask
    report: ValidationReport | None = None
    error: str | None = None
    timing_ms: dict[str, float] = field(default_factory=dict)
    metrics_snapshot: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "name": self.task.name,
            "error": self.error,
            "timing_ms": self.timing_ms,
            "metrics_snapshot": self.metrics_snapshot,
        }


@dataclass
class BatchResult:
    """Aggregate batch execution result."""
    tasks: list[TaskResult] = field(default_factory=list)
    total_timing_ms: float = 0.0
    passed: int = 0
    failed: int = 0
    error_count: int = 0
    domain_counts: dict[str, int] = field(default_factory=dict)
    vendor_pair_counts: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "total_tasks": len(self.tasks),
                "passed": self.passed,
                "failed": self.failed,
                "errors": self.error_count,
                "total_timing_ms": round(self.total_timing_ms, 2),
                "domain_counts": self.domain_counts,
                "vendor_pair_counts": self.vendor_pair_counts,
            },
            "results": [t.to_dict() for t in self.tasks],
        }


# Profile key resolver: short vendor name → full profile key.
# Supports both short names (e.g. "h3c") and full keys (e.g. "h3c_comware").
# For FIREWALL domain, use the explicit profile key like "huawei_usg".
_VENDOR_TO_PROFILE_KEY: dict[str, str] = {
    "cisco": "cisco_ios_xe",
    "h3c": "h3c_comware",
    "huawei": "huawei_vrp",
    "ruijie": "ruijie_rgos",
    "hillstone": "hillstone_stoneos",
    "topsec": "topsec_tos",
    "dptech": "dptech_fw",
    # FIREWALL profile explicit keys (identity-overrides for domain resolution)
    "huawei_usg": "huawei_usg",
    "huawei_vrp": "huawei_vrp",
}


def _resolve_profile_key(name: str) -> str:
    return _VENDOR_TO_PROFILE_KEY.get(name, name)


def _build_validator(
    source_vendor: str, target_vendor: str, domain: str,
) -> CompositeValidator | None:
    try:
        from core.domain import DeviceDomain
        from core.validator.coverage_validator import CoverageValidator
        from core.validator.residue_validator import ResidueValidator
        from core.validator.semantic_validator import SemanticValidator

        domain_enum = DeviceDomain(domain)
        init_profiles()
        tgt_key = _resolve_profile_key(target_vendor)
        tgt_profile = get_profile(tgt_key)
        if tgt_profile is None:
            return None
        return CompositeValidator(
            residue_validator=ResidueValidator(profile=tgt_profile),
            coverage_validator=CoverageValidator(
                src_domain=domain_enum, tgt_domain=domain_enum,
            ),
            semantic_validator=SemanticValidator(
                src_domain=domain_enum, tgt_domain=domain_enum,
            ),
        )
    except Exception:
        return None


def _extract_metrics(report: ValidationReport) -> dict:
    d = report.to_dict()
    return {
        "total_issues": d.get("total_issues", 0),
        "deployable": d.get("deployable"),
        "manual_review_required": d.get("manual_review_required"),
        "capability_verifiability_rate": (
            report.metadata.get("capability_metrics", {}).get("verifiability_rate")
        ),
        "coverage_verifiability_rate": (
            report.metadata.get("coverage_metrics", {}).get("coverage_verifiability_rate")
        ),
        "overall_verifiability_index": (
            report.metadata.get("capability_metrics", {}).get("overall_verifiability_index")
        ),
    }


def run_batch(
    tasks: list[BatchTask],
    progress_callback: Callable[[int, int], None] | None = None,
) -> BatchResult:
    """Execute a batch of validation tasks sequentially.

    Args:
        tasks: List of BatchTask specifications.
        progress_callback: Optional (current, total) callback.

    Returns:
        BatchResult with per-task results and aggregate summary.
    """
    init_profiles()
    result = BatchResult()
    validator_cache: dict[str, CompositeValidator] = {}
    t_start = time.perf_counter()

    for i, task in enumerate(tasks):
        tr = _run_task(task, validator_cache)
        result.tasks.append(tr)
        if tr.error:
            result.error_count += 1
        elif tr.report and tr.report.deployable():
            result.passed += 1
        else:
            result.failed += 1
        result.domain_counts[task.domain] = result.domain_counts.get(task.domain, 0) + 1
        pair_key = f"{task.source_vendor}→{task.target_vendor}"
        result.vendor_pair_counts[pair_key] = result.vendor_pair_counts.get(pair_key, 0) + 1
        if progress_callback:
            progress_callback(i + 1, len(tasks))

    result.total_timing_ms = round(
        (time.perf_counter() - t_start) * 1000, 2,
    )
    return result


def _run_task(
    task: BatchTask,
    validator_cache: dict[str, CompositeValidator],
) -> TaskResult:
    result = TaskResult(task=task)
    t_start = time.perf_counter()

    try:
        cache_key = f"{task.source_vendor}:{task.target_vendor}:{task.domain}"
        cv = validator_cache.get(cache_key)
        if cv is None:
            cv = _build_validator(
                task.source_vendor, task.target_vendor, task.domain,
            )
            if cv:
                validator_cache[cache_key] = cv

        if cv is None:
            result.error = f"cannot build validator for {cache_key}"
            result.timing_ms["total"] = round(
                (time.perf_counter() - t_start) * 1000, 2,
            )
            return result

        init_profiles()
        src_key = _resolve_profile_key(task.source_vendor)
        tgt_key = _resolve_profile_key(task.target_vendor)
        src_profile = get_profile(src_key)
        tgt_profile = get_profile(tgt_key)

        from core.domain import DeviceDomain
        t0 = time.perf_counter()
        report = cv.validate(
            target_config=task.target_config,
            ir=task.ir, render_result=task.render_result,
            src_profile=src_profile, tgt_profile=tgt_profile,
            src_domain=DeviceDomain(task.domain),
            tgt_domain=DeviceDomain(task.domain),
        )
        result.timing_ms["validate"] = round(
            (time.perf_counter() - t0) * 1000, 2,
        )

        result.report = report
        result.metrics_snapshot = _extract_metrics(report)
        result.timing_ms["total"] = round(
            (time.perf_counter() - t_start) * 1000, 2,
        )

    except Exception as e:
        result.error = str(e)
        result.timing_ms["total"] = round(
            (time.perf_counter() - t_start) * 1000, 2,
        )

    return result
