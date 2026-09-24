"""Investigation detail routes for WinHunt."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flask import Blueprint, abort, render_template
from jinja2 import TemplateNotFound

from app.services.winhunt_service import WinHuntService


investigation_bp = Blueprint(
    "investigation",
    __name__,
)


def _project_root() -> Path:
    """Resolve the repository root from this file's location."""
    return Path(__file__).resolve().parents[2]


def _load_sample_events() -> list[dict[str, Any]]:
    """Load the frozen WinHunt telemetry sample used by the dashboard."""
    sample_path = _project_root() / "data" / "sample_events.json"

    if not sample_path.exists():
        abort(500, description=f"Sample telemetry file not found: {sample_path}")

    try:
        with sample_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        abort(500, description=f"Unable to load sample telemetry: {exc}")

    if not isinstance(payload, list):
        abort(500, description="Sample telemetry must be a JSON list of event objects.")

    if not all(isinstance(event, dict) for event in payload):
        abort(500, description="Sample telemetry must contain only JSON object entries.")

    return payload


def _normalize_finding_type(value: Any) -> str:
    """Normalize missing or placeholder finding_type values for safe comparison."""
    if value is None:
        return "unknown"

    if isinstance(value, str):
        normalized = value.strip()
        if not normalized or normalized.lower() == "unknown":
            return "unknown"
        return normalized

    return value


def _is_same_finding(
    candidate: dict[str, Any],
    reference: dict[str, Any],
) -> bool:
    """Return True when two finding dictionaries represent the same finding."""
    if candidate is reference:
        return True

    for key in ("finding_id", "id"):
        candidate_value = candidate.get(key)
        reference_value = reference.get(key)

        if candidate_value is not None and reference_value is not None:
            if candidate_value == reference_value:
                return True

    def canonicalize(record: dict[str, Any]) -> dict[str, Any]:
        normalized: dict[str, Any] = {}

        for key, value in record.items():
            # Correlation normalization may add optional fields as None.
            # Treat an absent field and an explicit None as equivalent.
            if value is None:
                continue

            if key == "finding_type":
                if isinstance(value, str):
                    text = value.strip()
                    if not text or text.lower() == "unknown":
                        normalized[key] = "unknown"
                    else:
                        normalized[key] = text
                else:
                    normalized[key] = value
            else:
                normalized[key] = value

        if "finding_type" not in normalized:
            normalized["finding_type"] = "unknown"

        return normalized

    return canonicalize(candidate) == canonicalize(reference)

@investigation_bp.get("/investigate/<int:finding_index>")
def investigation(finding_index: int) -> str:
    """Render the analyst investigation page for a specific finding."""
    events = _load_sample_events()
    result = WinHuntService().analyze_events(events)
    findings = result.get("findings", [])

    if not isinstance(findings, list) or not findings:
        abort(404, description="Finding not found.")

    if finding_index < 0 or finding_index >= len(findings):
        abort(404, description="Finding not found.")

    finding = findings[finding_index]
    related_chains: list[dict[str, Any]] = []

    for chain in result.get("chains", []):
        chain_findings = chain.get("findings", [])
        if not isinstance(chain_findings, list):
            continue

        if any(
            _is_same_finding(finding, item)
            for item in chain_findings
            if isinstance(item, dict)
        ):
            related_chains.append(chain)

    try:
        return render_template(
            "investigation.html",
            finding=finding,
            related_chains=related_chains,
            finding_index=finding_index,
        )
    except TemplateNotFound as exc:
        abort(503, description=f"Investigation template is unavailable: {exc}")
