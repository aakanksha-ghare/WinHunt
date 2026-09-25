"""Threat-hunting query routes for WinHunt."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from flask import Blueprint, abort, render_template, request

from app.services.winhunt_service import WinHuntService


hunting_bp = Blueprint(
    "hunting",
    __name__,
    url_prefix="/hunt",
)


HUNT_QUERIES: dict[str, dict[str, str]] = {
    "office_to_powershell": {
        "label": "Office → PowerShell",
        "description": (
            "Find findings where Microsoft Office applications "
            "spawned PowerShell or pwsh."
        ),
    },
    "encoded_powershell": {
        "label": "Encoded PowerShell",
        "description": (
            "Find findings involving PowerShell encoded-command "
            "execution."
        ),
    },
    "appdata_processes": {
        "label": "Processes from AppData",
        "description": (
            "Find findings involving executable activity from "
            "AppData or Temp locations."
        ),
    },
    "failed_login_bursts": {
        "label": "Failed Login Bursts",
        "description": (
            "Find authentication findings representing bursts "
            "of failed logon activity."
        ),
    },
    "suspicious_process_chains": {
        "label": "Suspicious Process Chains",
        "description": (
            "Find correlated investigation chains containing "
            "process-based relationships."
        ),
    },
}


OFFICE_PROCESS_NAMES = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
}


TELEMETRY_CONTEXT_WINDOW_SECONDS = 30 * 60


def _normalized(value: Any) -> str:
    """Return a trimmed lowercase string representation."""
    if value is None:
        return ""

    return str(value).strip().lower()


def _evidence(finding: dict[str, Any]) -> dict[str, Any]:
    """Return the finding evidence dictionary."""
    evidence = finding.get("evidence")

    if isinstance(evidence, dict):
        return evidence

    return {}


def _finding_type(finding: dict[str, Any]) -> str:
    """Return the normalized finding type."""
    return _normalized(finding.get("finding_type"))


def _rule_id(finding: dict[str, Any]) -> str:
    """Return the normalized WinHunt rule identifier."""
    return _normalized(finding.get("rule_id"))


def _process_name(finding: dict[str, Any]) -> str:
    """Return the process name from finding or evidence."""
    evidence = _evidence(finding)

    return _normalized(
        finding.get("process")
        or evidence.get("process")
        or evidence.get("child_process")
    )


def _parent_process_name(finding: dict[str, Any]) -> str:
    """Return the parent process name from finding or evidence."""
    evidence = _evidence(finding)

    return _normalized(
        finding.get("parent_process")
        or evidence.get("parent_process")
        or evidence.get("parent_process_name")
    )


def _command_line(finding: dict[str, Any]) -> str:
    """Return the command line from finding or evidence."""
    evidence = _evidence(finding)

    return _normalized(
        finding.get("command_line")
        or evidence.get("command_line")
    )


def _path_values(finding: dict[str, Any]) -> list[str]:
    """Return normalized path-like values from finding evidence."""
    evidence = _evidence(finding)

    values = [
        finding.get("path"),
        finding.get("file_path"),
        finding.get("location"),
        evidence.get("path"),
        evidence.get("file_path"),
        evidence.get("location"),
        evidence.get("image"),
        evidence.get("image_path"),
        evidence.get("target_file_path"),
    ]

    return [
        _normalized(value)
        for value in values
        if value is not None and _normalized(value)
    ]


def _parse_timestamp(value: Any) -> datetime | None:
    """Parse common WinHunt timestamp representations as UTC."""
    if value is None:
        return None

    if isinstance(value, datetime):
        timestamp = value
    elif isinstance(value, str):
        text = value.strip()

        if not text:
            return None

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        try:
            timestamp = datetime.fromisoformat(text)
        except ValueError:
            try:
                timestamp = datetime.strptime(
                    text,
                    "%Y-%m-%d %H:%M:%S",
                )
            except ValueError:
                return None
    elif isinstance(value, (int, float)):
        try:
            timestamp = datetime.fromtimestamp(
                float(value),
                tz=timezone.utc,
            )
        except (OverflowError, OSError, ValueError):
            return None
    else:
        return None

    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    else:
        timestamp = timestamp.astimezone(timezone.utc)

    return timestamp


def _is_office_to_powershell(finding: dict[str, Any]) -> bool:
    """Return True for Office-to-PowerShell findings."""
    if _finding_type(finding) == "office_to_powershell":
        return True

    if _rule_id(finding) == "winhunt-002":
        return True

    process = _process_name(finding)
    parent_process = _parent_process_name(finding)

    return (
        process in {"powershell.exe", "pwsh.exe"}
        and parent_process in OFFICE_PROCESS_NAMES
    )


def _is_encoded_powershell(finding: dict[str, Any]) -> bool:
    """Return True for encoded PowerShell findings."""
    if _finding_type(finding) == "encoded_powershell":
        return True

    if _rule_id(finding) == "winhunt-001":
        return True

    command_line = _command_line(finding)
    padded_command_line = f" {command_line} "

    return (
        "powershell" in command_line
        and (
            " -enc " in padded_command_line
            or " -encodedcommand " in padded_command_line
        )
    )


def _is_appdata_process(finding: dict[str, Any]) -> bool:
    """Return True for executable activity from AppData or Temp."""
    if _finding_type(finding) == "suspicious_executable_location":
        return True

    if _rule_id(finding) == "winhunt-003":
        return True

    return any(
        "\\appdata\\" in value
        or "/appdata/" in value
        or "\\temp\\" in value
        or "/temp/" in value
        for value in _path_values(finding)
    )


def _is_failed_login_burst(finding: dict[str, Any]) -> bool:
    """Return True for failed-login burst findings."""
    return _finding_type(finding) == "failed_login_burst"


def _is_process_chain(chain: dict[str, Any]) -> bool:
    """Return True for chains containing process relationships."""
    findings = chain.get("findings", [])

    if not isinstance(findings, list) or len(findings) < 2:
        return False

    process_reasons = {
        "shared_process",
        "shared_pid",
        "shared_process_guid",
        "parent_child_process",
    }

    correlation_reasons = chain.get("correlation_reasons", [])

    if not isinstance(correlation_reasons, list):
        return False

    for entry in correlation_reasons:
        if not isinstance(entry, dict):
            continue

        reasons = entry.get("reasons", [])

        if not isinstance(reasons, list):
            continue

        if process_reasons.intersection(
            str(reason)
            for reason in reasons
        ):
            return True

    return False


def _canonical_finding(
    finding: dict[str, Any],
) -> dict[str, Any]:
    """Create a comparison form that ignores correlation-added None fields."""
    normalized: dict[str, Any] = {}

    for key, value in finding.items():
        if value is None:
            continue

        if key == "finding_type":
            text = _normalized(value)
            normalized[key] = text or "unknown"
        else:
            normalized[key] = value

    if "finding_type" not in normalized:
        normalized["finding_type"] = "unknown"

    return normalized


def _same_finding(
    candidate: dict[str, Any],
    reference: dict[str, Any],
) -> bool:
    """Match an original finding against a finding embedded in a chain."""
    if candidate is reference:
        return True

    for key in ("finding_id", "id"):
        candidate_value = candidate.get(key)
        reference_value = reference.get(key)

        if (
            candidate_value is not None
            and reference_value is not None
            and candidate_value == reference_value
        ):
            return True

    return _canonical_finding(candidate) == _canonical_finding(reference)


def _investigation_index(
    finding: dict[str, Any],
    findings: list[dict[str, Any]],
) -> int | None:
    """Return the dashboard finding index for a finding."""
    for index, candidate in enumerate(findings):
        if _same_finding(finding, candidate):
            return index

    return None


def _build_telemetry_context(
    events: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Index telemetry context by process PID."""
    context: dict[str, list[dict[str, Any]]] = {}

    for event in events:
        if not isinstance(event, dict):
            continue

        pid = event.get("pid")

        if pid is None:
            pid = event.get("new_process_id")

        timestamp = _parse_timestamp(
            event.get("timestamp")
        )

        if pid is None or timestamp is None:
            continue

        user = event.get("user") or event.get("subject_user")
        host = event.get("host")

        if not user and not host:
            continue

        pid_key = str(pid)

        context.setdefault(pid_key, []).append(
            {
                "timestamp": timestamp,
                "user": user,
                "host": host,
                "process": _normalized(event.get("process") or event.get("new_process_name")),
            }
        )

    for entries in context.values():
        entries.sort(
            key=lambda item: item["timestamp"]
        )

    return context


def _enrich_finding_display(
    finding: dict[str, Any],
    telemetry_context: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    """Add display-only host/user context from nearby telemetry."""
    result = dict(finding)

    evidence = _evidence(finding)

    if not result.get("host") and evidence.get("host"):
        result["host"] = evidence["host"]

    if not result.get("user") and evidence.get("user"):
        result["user"] = evidence["user"]

    pid = finding.get("pid")
    timestamp = _parse_timestamp(
        finding.get("timestamp")
    )

    if pid is None or timestamp is None:
        return result

    candidates = telemetry_context.get(
        str(pid),
        [],
    )

    if not candidates:
        return result

    finding_process = _process_name(finding)

    nearby: list[tuple[float, dict[str, Any]]] = []

    for candidate in candidates:
        candidate_timestamp = candidate.get("timestamp")

        if not isinstance(candidate_timestamp, datetime):
            continue

        distance = abs(
            (
                candidate_timestamp - timestamp
            ).total_seconds()
        )

        if distance > TELEMETRY_CONTEXT_WINDOW_SECONDS:
            continue

        candidate_process = _normalized(
            candidate.get("process")
        )

        process_penalty = 0.0

        if finding_process and candidate_process:
            if finding_process != candidate_process:
                process_penalty = 5.0

        nearby.append(
            (
                distance + process_penalty,
                candidate,
            )
        )

    nearby.sort(
        key=lambda item: item[0]
    )

    for _, candidate in nearby:
        if not result.get("host") and candidate.get("host"):
            result["host"] = candidate["host"]

        if not result.get("user") and candidate.get("user"):
            result["user"] = candidate["user"]

        if result.get("host") and result.get("user"):
            break

    return result


def _finding_matches(
    finding: dict[str, Any],
    query: str,
) -> bool:
    """Apply a named hunting query to a finding."""
    matchers = {
        "office_to_powershell": _is_office_to_powershell,
        "encoded_powershell": _is_encoded_powershell,
        "appdata_processes": _is_appdata_process,
        "failed_login_bursts": _is_failed_login_burst,
    }

    matcher = matchers.get(query)

    if matcher is None:
        return False

    return matcher(finding)


def _load_sample_events() -> list[dict[str, Any]]:
    """Load and validate the frozen sample telemetry dataset."""
    project_root = Path(__file__).resolve().parents[2]

    sample_path = (
        project_root
        / "data"
        / "sample_events.json"
    )

    if not sample_path.exists():
        abort(
            500,
            description=(
                f"Sample telemetry file not found: {sample_path}"
            ),
        )

    try:
        with sample_path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        abort(
            500,
            description=(
                f"Unable to load sample telemetry: {exc}"
            ),
        )

    if not isinstance(payload, list):
        abort(
            500,
            description=(
                "Sample telemetry must be a JSON list of events."
            ),
        )

    if not all(
        isinstance(event, dict)
        for event in payload
    ):
        abort(
            500,
            description=(
                "Sample telemetry must contain only event objects."
            ),
        )

    return payload


@hunting_bp.get("/")
def hunting() -> str:
    """Render the WinHunt threat-hunting query interface."""
    selected_query = _normalized(
        request.args.get("query")
    )

    if selected_query not in HUNT_QUERIES:
        selected_query = "office_to_powershell"

    events = _load_sample_events()

    result = WinHuntService().analyze_events(
        events
    )

    telemetry_context = _build_telemetry_context(
        events
    )

    findings = result.get("findings", [])
    chains = result.get("chains", [])

    if not isinstance(findings, list):
        findings = []

    if not isinstance(chains, list):
        chains = []

    query_results: list[dict[str, Any]] = []
    chain_results: list[dict[str, Any]] = []

    if selected_query == "suspicious_process_chains":
        for chain in chains:
            if not isinstance(chain, dict):
                continue

            if not _is_process_chain(chain):
                continue

            finding_index = None

            chain_findings = chain.get(
                "findings",
                [],
            )

            if isinstance(chain_findings, list):
                for chain_finding in chain_findings:
                    if not isinstance(chain_finding, dict):
                        continue

                    finding_index = _investigation_index(
                        chain_finding,
                        findings,
                    )

                    if finding_index is not None:
                        break

            chain_results.append(
                {
                    "chain": chain,
                    "finding_index": finding_index,
                }
            )

    else:
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue

            if not _finding_matches(
                finding,
                selected_query,
            ):
                continue

            display_finding = _enrich_finding_display(
                finding,
                telemetry_context,
            )

            query_results.append(
                {
                    "finding": display_finding,
                    "finding_index": index,
                }
            )

    return render_template(
        "hunting.html",
        queries=HUNT_QUERIES,
        selected_query=selected_query,
        selected_label=HUNT_QUERIES[selected_query]["label"],
        selected_description=HUNT_QUERIES[selected_query]["description"],
        results=query_results,
        chain_results=chain_results,
        summary=result.get("summary", {}),
    )


__all__ = [
    "hunting_bp",
    "HUNT_QUERIES",
]