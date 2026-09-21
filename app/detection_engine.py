"""Detection engine that orchestrates the registered normalized-event rules."""

from __future__ import annotations

from collections.abc import Iterable

from rules.file_execution import detect_suspicious_executable_location
from rules.persistence import detect_scheduled_task_creation
from rules.powershell import detect_encoded_powershell
from rules.process import detect_office_to_powershell

DETECTION_RULES = [
    detect_encoded_powershell,
    detect_office_to_powershell,
    detect_suspicious_executable_location,
    detect_scheduled_task_creation,
]


def detect_event(event):
    """Run all registered detections for a single normalized event."""
    if not isinstance(event, dict):
        return []

    findings = []
    for rule in DETECTION_RULES:
        finding = rule(event)
        if finding is None:
            continue
        if not isinstance(finding, dict):
            raise TypeError(f"Detection rule {rule.__name__} returned a non-dictionary result")
        findings.append(finding)

    return findings


def detect_events(events):
    """Run all registered detections for each event and flatten the findings."""
    if events is None:
        return []

    findings = []
    for event in events:
        findings.extend(detect_event(event))
    return findings
