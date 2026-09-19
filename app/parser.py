"""Utilities for normalizing Windows telemetry events."""

from __future__ import annotations

from typing import Any


def normalize_process_event(event: dict[str, Any]) -> dict[str, Any]:
    """Return a normalized dictionary for a Windows process creation event."""
    return {
        "timestamp": event["timestamp"],
        "pid": event["pid"],
        "process": event["process"],
        "parent_pid": event["parent_pid"],
        "parent_process": event["parent_process"],
        "command_line": event["command_line"],
        "user": event["user"],
        "path": event["path"],
    }


def normalize_network_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Windows network connection event."""
    return {
        "timestamp": event["timestamp"],
        "pid": event["pid"],
        "process": event["process"],
        "dest_ip": event["dest_ip"],
        "dest_port": event["dest_port"],
        "dest_domain": event["dest_domain"],
        "protocol": event["protocol"],
        "user": event["user"],
    }


def normalize_file_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Windows file creation or modification event."""
    return {
        "timestamp": event["timestamp"],
        "pid": event["pid"],
        "process": event["process"],
        "action": event["action"],
        "file_path": event["file_path"],
        "user": event["user"],
    }


def normalize_logon_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Windows successful or failed logon event."""
    return {
        "timestamp": event["timestamp"],
        "event_id": event["event_id"],
        "user": event["user"],
        "source": event["source"],
        "status": event["status"],
        "logon_type": event["logon_type"],
        "host": event["host"],
    }


def normalize_scheduled_task_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize a Windows scheduled task creation event."""
    return {
        "timestamp": event["timestamp"],
        "event_id": event["event_id"],
        "task_name": event["task_name"],
        "action": event["action"],
        "created_by_process": event["created_by_process"],
        "created_by_pid": event["created_by_pid"],
        "user": event["user"],
        "host": event["host"],
    }


def parse_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize all supported telemetry event types while preserving source order."""
    normalized_events: list[dict[str, Any]] = []

    for event in events:
        event_id = event.get("event_id")
        if event_id == 1:
            record = normalize_process_event(event)
            record["event_type"] = "process"
        elif event_id == 3:
            record = normalize_network_event(event)
            record["event_type"] = "network"
        elif event_id == 11:
            record = normalize_file_event(event)
            record["event_type"] = "file"
        elif event_id in {4624, 4625}:
            record = normalize_logon_event(event)
            record["event_type"] = "logon"
        elif event_id == 4698:
            record = normalize_scheduled_task_event(event)
            record["event_type"] = "scheduled_task"
        else:
            continue

        normalized_events.append(record)

    return normalized_events


def parse_process_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize all raw Event ID 1 telemetry entries while preserving order."""
    normalized_events: list[dict[str, Any]] = []

    for event in events:
        if event.get("event_id") == 1:
            normalized_events.append(normalize_process_event(event))

    return normalized_events
