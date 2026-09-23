"""Dashboard routes for WinHunt."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from flask import Blueprint, abort, render_template
from jinja2 import TemplateNotFound

from app.services.winhunt_service import WinHuntService


dashboard_bp = Blueprint(
    "dashboard",
    __name__,
    url_prefix="/",
)


def _project_root() -> Path:
    """Resolve the repository root from this file's location."""
    return Path(__file__).resolve().parents[2]


def _load_sample_events() -> list[dict[str, Any]]:
    """Load the project's sample telemetry file and validate its structure."""
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


@dashboard_bp.get("/")
def dashboard() -> str:
    """Render the WinHunt dashboard using the frozen sample telemetry dataset."""
    events = _load_sample_events()
    result = WinHuntService().analyze_events(events)

    try:
        return render_template(
            "dashboard.html",
            summary=result.get("summary", {}),
            findings=result.get("findings", []),
            chains=result.get("chains", []),
        )
    except TemplateNotFound as exc:
        abort(503, description=f"Dashboard template is unavailable: {exc}")
