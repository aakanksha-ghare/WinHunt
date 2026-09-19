"""Normalize external EVTX CSV records into WinHunt's shared event model."""

from __future__ import annotations

import numbers
import os
from pathlib import Path
from typing import Any, Iterable

import pandas as pd


def _is_missing(value: Any) -> bool:
    """Return True when a value is null-like or intentionally empty."""
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == "" or value.strip().lower() in {"nan", "none", "null"}
    try:
        return bool(pd.isna(value))
    except TypeError:
        return False


def _coerce_value(value: Any) -> Any:
    """Convert pandas null values to None while preserving valid content."""
    if _is_missing(value):
        return None
    return value


def _first_non_null(*values: Any) -> Any:
    """Return the first non-empty, non-null value from a set of candidates."""
    for value in values:
        coerced = _coerce_value(value)
        if coerced is not None:
            return coerced
    return None


def _as_int(value: Any) -> int | None:
    """Safely convert numeric strings, floats, and hex values to integers."""
    value = _coerce_value(value)
    if value is None:
        return None

    if isinstance(value, bool):
        return None
    if isinstance(value, numbers.Integral):
        return int(value)
    if isinstance(value, numbers.Real):
        if float(value).is_integer():
            return int(value)
        return None

    text = str(value).strip()
    if not text:
        return None
    if text.lower().startswith("0x"):
        try:
            return int(text, 16)
        except ValueError:
            return None
    try:
        numeric = float(text)
    except ValueError:
        return None
    if not numeric.is_integer():
        return None
    return int(numeric)


def _as_text(value: Any) -> str | None:
    """Return a normalized string or None for missing values."""
    value = _coerce_value(value)
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    return text


def _basename(value: Any) -> str | None:
    """Extract the basename from a path, but only for string-like inputs."""
    text = _as_text(value)
    if text is None:
        return None
    if os.path.sep in text or "/" in text:
        return os.path.basename(text)
    return text


def _timestamp_from_record(record: dict[str, Any]) -> str | None:
    """Return the timestamp field used by the given CSV row when available."""
    for key in ("SystemTime", "UtcTime", "timestamp", "Timestamp"):
        value = _as_text(record.get(key))
        if value:
            return value
    return None


def normalize_external_process_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize Sysmon Event ID 1 and Windows Security Event ID 4688."""
    event_id = _as_int(record.get("EventID"))
    if event_id not in {1, 4688}:
        return None

    if event_id == 1:
        pid = _as_int(_first_non_null(record.get("ProcessId"), record.get("ProcessID")))
        process_name = _basename(_first_non_null(record.get("Image"), record.get("ProcessName")))
        path = _as_text(_first_non_null(record.get("Image"), record.get("ProcessName")))
        parent_pid = _as_int(_first_non_null(record.get("ParentProcessId"), record.get("ParentProcessID")))
        parent_process = _basename(_first_non_null(record.get("ParentImage"))) or _as_text(record.get("ParentImage"))
        command_line = _as_text(record.get("CommandLine"))
        user = _as_text(_first_non_null(record.get("User"), record.get("UserID"), record.get("TargetUserName"), record.get("SubjectUserName")))
    else:
        pid = _as_int(_first_non_null(record.get("NewProcessId"), record.get("ProcessId"), record.get("ProcessID")))
        process_name = _basename(_first_non_null(record.get("NewProcessName"), record.get("Image"))) or _as_text(record.get("NewProcessName"))
        path = _as_text(_first_non_null(record.get("NewProcessName"), record.get("Image")))
        parent_pid = _as_int(_first_non_null(record.get("ParentProcessId"), record.get("ParentProcessID")))
        parent_process = _basename(_first_non_null(record.get("ParentImage"))) or _as_text(record.get("ParentImage"))
        command_line = _as_text(record.get("CommandLine"))
        user = _as_text(_first_non_null(record.get("User"), record.get("UserID"), record.get("SubjectUserName"), record.get("TargetUserName")))

    return {
        "timestamp": _timestamp_from_record(record),
        "event_id": event_id,
        "event_type": "process",
        "pid": pid,
        "process": process_name,
        "parent_pid": parent_pid,
        "parent_process": parent_process,
        "command_line": command_line,
        "user": user,
        "path": path,
    }


def normalize_external_network_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a Sysmon network connection event."""
    if _as_int(record.get("EventID")) != 3:
        return None

    pid = _as_int(_first_non_null(record.get("ProcessId"), record.get("ProcessID")))
    process_name = _basename(_first_non_null(record.get("Image"), record.get("ProcessName"))) or _as_text(record.get("ProcessName"))
    dest_ip = _as_text(_first_non_null(record.get("DestinationIp"), record.get("DestAddress"), record.get("IpAddress")))
    dest_port = _as_int(_first_non_null(record.get("DestinationPort"), record.get("DestPort"), record.get("IpPort")))
    protocol = _as_text(record.get("Protocol"))
    user = _as_text(_first_non_null(record.get("User"), record.get("UserID"), record.get("username")))

    return {
        "timestamp": _timestamp_from_record(record),
        "event_id": 3,
        "event_type": "network",
        "pid": pid,
        "process": process_name,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "protocol": protocol,
        "user": user,
    }


def normalize_external_image_load_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a Sysmon image-load event."""
    if _as_int(record.get("EventID")) != 7:
        return None

    pid = _as_int(_first_non_null(record.get("ProcessId"), record.get("ProcessID")))
    image = _as_text(record.get("Image"))
    image_loaded = _as_text(record.get("ImageLoaded"))
    process_name = _basename(image) or _as_text(record.get("ProcessName"))
    user = _as_text(_first_non_null(record.get("User"), record.get("UserID")))

    return {
        "timestamp": _timestamp_from_record(record),
        "event_id": 7,
        "event_type": "image_load",
        "pid": pid,
        "process": process_name,
        "image": image,
        "image_loaded": image_loaded,
        "user": user,
    }


def normalize_external_remote_thread_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a Sysmon remote-thread event."""
    if _as_int(record.get("EventID")) != 8:
        return None

    source_pid = _as_int(record.get("SourceProcessId"))
    target_pid = _as_int(record.get("TargetProcessId"))
    source_process = _basename(_first_non_null(record.get("SourceImage"))) or _as_text(record.get("SourceImage"))
    target_process = _basename(_first_non_null(record.get("TargetImage"))) or _as_text(record.get("TargetImage"))
    start_address = _as_text(_first_non_null(record.get("StartAddress"), record.get("StartModule")))

    return {
        "timestamp": _timestamp_from_record(record),
        "event_id": 8,
        "event_type": "remote_thread",
        "source_pid": source_pid,
        "source_process": source_process,
        "target_pid": target_pid,
        "target_process": target_process,
        "start_address": start_address,
    }


def normalize_external_process_access_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a Sysmon process-access event."""
    if _as_int(record.get("EventID")) != 10:
        return None

    source_pid = _as_int(record.get("SourceProcessId"))
    target_pid = _as_int(record.get("TargetProcessId"))
    source_process = _basename(_first_non_null(record.get("SourceImage"))) or _as_text(record.get("SourceImage"))
    target_process = _basename(_first_non_null(record.get("TargetImage"))) or _as_text(record.get("TargetImage"))
    granted_access = _as_text(record.get("GrantedAccess"))

    return {
        "timestamp": _timestamp_from_record(record),
        "event_id": 10,
        "event_type": "process_access",
        "source_pid": source_pid,
        "source_process": source_process,
        "target_pid": target_pid,
        "target_process": target_process,
        "granted_access": granted_access,
    }


def normalize_external_file_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize Sysmon file-related events and ADS changes (including Event ID 15)."""
    event_id = _as_int(record.get("EventID"))
    if event_id not in {11, 15, 23, 26, 29}:
        return None

    pid = _as_int(_first_non_null(record.get("ProcessId"), record.get("ProcessID")))
    process_name = _basename(_first_non_null(record.get("Image"), record.get("ProcessName"))) or _as_text(record.get("ProcessName"))
    file_path = _as_text(_first_non_null(record.get("TargetFilename"), record.get("RelativeTargetName"), record.get("Path"), record.get("FilePath")))
    action = _as_text(_first_non_null(record.get("Action"), record.get("Operation"), record.get("EventType")))
    user = _as_text(_first_non_null(record.get("User"), record.get("UserID")))

    return {
        "timestamp": _timestamp_from_record(record),
        "event_id": event_id,
        "event_type": "file",
        "pid": pid,
        "process": process_name,
        "file_path": file_path,
        "action": action,
        "user": user,
    }


def normalize_external_registry_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize registry events (Event IDs 12 and 13)."""
    event_id = _as_int(record.get("EventID"))
    if event_id not in {12, 13}:
        return None

    pid = _as_int(_first_non_null(record.get("ProcessId"), record.get("ProcessID")))
    process_name = _basename(_first_non_null(record.get("Image"), record.get("ProcessName"))) or _as_text(record.get("ProcessName"))
    registry_key = _as_text(_first_non_null(record.get("TargetObject"), record.get("ObjectName")))
    details = _as_text(record.get("Details"))
    user = _as_text(_first_non_null(record.get("User"), record.get("UserID")))

    return {
        "timestamp": _timestamp_from_record(record),
        "event_id": event_id,
        "event_type": "registry",
        "pid": pid,
        "process": process_name,
        "registry_key": registry_key,
        "details": details,
        "user": user,
    }


def normalize_external_dns_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a Sysmon DNS query event."""
    if _as_int(record.get("EventID")) != 22:
        return None

    pid = _as_int(_first_non_null(record.get("ProcessId"), record.get("ProcessID")))
    process_name = _basename(_first_non_null(record.get("Image"), record.get("ProcessName"))) or _as_text(record.get("ProcessName"))
    query_name = _as_text(record.get("QueryName"))
    query_results = _as_text(record.get("QueryResults"))
    user = _as_text(_first_non_null(record.get("User"), record.get("UserID")))

    return {
        "timestamp": _timestamp_from_record(record),
        "event_id": 22,
        "event_type": "dns",
        "pid": pid,
        "process": process_name,
        "query_name": query_name,
        "query_results": query_results,
        "user": user,
    }


def normalize_external_named_pipe_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a Sysmon named-pipe event."""
    event_id = _as_int(record.get("EventID"))
    if event_id not in {17, 18}:
        return None

    pid = _as_int(_first_non_null(record.get("ProcessId"), record.get("ProcessID")))
    process_name = _basename(_first_non_null(record.get("Image"), record.get("ProcessName"))) or _as_text(record.get("ProcessName"))
    pipe_name = _as_text(record.get("PipeName"))
    user = _as_text(_first_non_null(record.get("User"), record.get("UserID")))

    return {
        "timestamp": _timestamp_from_record(record),
        "event_id": event_id,
        "event_type": "named_pipe",
        "pid": pid,
        "process": process_name,
        "pipe_name": pipe_name,
        "user": user,
    }


def normalize_external_wmi_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize Sysmon WMI events."""
    event_id = _as_int(record.get("EventID"))
    if event_id not in {19, 20, 21}:
        return None

    pid = _as_int(_first_non_null(record.get("ProcessId"), record.get("ProcessID")))
    process_name = _basename(_first_non_null(record.get("Image"), record.get("ProcessName"))) or _as_text(record.get("ProcessName"))
    query = _as_text(_first_non_null(record.get("Query"), record.get("QueryName")))
    consumer = _as_text(record.get("Consumer"))
    operation = _as_text(record.get("Operation"))
    destination = _as_text(record.get("Destination"))
    user = _as_text(_first_non_null(record.get("User"), record.get("UserID")))

    return {
        "timestamp": _timestamp_from_record(record),
        "event_id": event_id,
        "event_type": "wmi",
        "pid": pid,
        "process": process_name,
        "query": query,
        "consumer": consumer,
        "operation": operation,
        "destination": destination,
        "user": user,
    }


def normalize_external_logon_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize Windows logon-related events into a common representation."""
    event_id = _as_int(record.get("EventID"))
    if event_id not in {4624, 4625, 4648, 4672, 4771}:
        return None

    if event_id == 4648:
        event_type = "explicit_credentials"
    elif event_id == 4672:
        event_type = "special_privileges"
    elif event_id == 4771:
        event_type = "kerberos_failure"
    else:
        event_type = "logon"

    user = _as_text(_first_non_null(record.get("TargetUserName"), record.get("SubjectUserName"), record.get("User"), record.get("TargetOutboundUserName")))
    source = _as_text(_first_non_null(record.get("WorkstationName"), record.get("SourceAddress"), record.get("IpAddress"), record.get("Computer")))
    host = _as_text(_first_non_null(record.get("Computer"), record.get("host")))

    normalized = {
        "timestamp": _timestamp_from_record(record),
        "event_id": event_id,
        "event_type": event_type,
        "user": user,
        "source": source,
        "host": host,
        "logon_type": _as_text(record.get("LogonType")) or _as_text(record.get("LogonProcessName")),
    }
    if event_id == 4624:
        normalized["status"] = "success"
    elif event_id == 4625:
        normalized["status"] = "failure"

    if event_id in {4672, 4771}:
        normalized["privilege_list"] = _as_text(record.get("PrivilegeList"))
    if event_id == 4771:
        normalized["service_name"] = _as_text(record.get("ServiceName"))
    return normalized


def normalize_external_scheduled_task_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize scheduled task creation or update events."""
    event_id = _as_int(record.get("EventID"))
    if event_id not in {4698, 4702}:
        return None

    task_name = _as_text(_first_non_null(record.get("TaskName"), record.get("TaskContentNew"), record.get("TaskContent")))
    action = _as_text(_first_non_null(record.get("Action"), record.get("TaskContent"), record.get("TaskContentNew"), record.get("CommandLine")))
    created_by_process = _basename(_first_non_null(record.get("Image"), record.get("ProcessName"))) or _as_text(_first_non_null(record.get("Image"), record.get("ProcessName")))
    created_by_pid = _as_int(_first_non_null(record.get("ProcessId"), record.get("ProcessID")))
    user = _as_text(_first_non_null(record.get("User"), record.get("UserID"), record.get("TargetUserName"), record.get("SubjectUserName")))
    host = _as_text(record.get("Computer"))

    return {
        "timestamp": _timestamp_from_record(record),
        "event_id": event_id,
        "event_type": "scheduled_task",
        "task_name": task_name,
        "action": action,
        "created_by_process": created_by_process,
        "created_by_pid": created_by_pid,
        "user": user,
        "host": host,
    }


def normalize_external_service_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a Windows service installation event."""
    if _as_int(record.get("EventID")) != 7045:
        return None

    return {
        "timestamp": _timestamp_from_record(record),
        "event_id": 7045,
        "event_type": "service",
        "service_name": _as_text(_first_non_null(record.get("ServiceName"), record.get("Service"))),
        "image_path": _as_text(_first_non_null(record.get("ImagePath"), record.get("Path"), record.get("Image"))),
        "service_type": _as_text(record.get("ServiceType")),
        "start_type": _as_text(record.get("StartType")),
        "user": _as_text(_first_non_null(record.get("User"), record.get("UserID"))),
    }


def normalize_external_event(record: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize one supported external EVTX record into the common WinHunt event model."""
    if record is None:
        return None

    event_id = _as_int(record.get("EventID"))
    if event_id is None:
        return None

    if event_id in {1, 4688}:
        return normalize_external_process_event(record)
    if event_id == 3:
        return normalize_external_network_event(record)
    if event_id == 7:
        return normalize_external_image_load_event(record)
    if event_id == 8:
        return normalize_external_remote_thread_event(record)
    if event_id == 10:
        return normalize_external_process_access_event(record)
    if event_id in {11, 15, 23, 26, 29}:
        return normalize_external_file_event(record)
    if event_id in {12, 13}:
        return normalize_external_registry_event(record)
    if event_id == 22:
        return normalize_external_dns_event(record)
    if event_id in {17, 18}:
        return normalize_external_named_pipe_event(record)
    if event_id in {19, 20, 21}:
        return normalize_external_wmi_event(record)
    if event_id in {4624, 4625, 4648, 4672, 4771}:
        return normalize_external_logon_event(record)
    if event_id in {4698, 4702}:
        return normalize_external_scheduled_task_event(record)
    if event_id == 7045:
        return normalize_external_service_event(record)
    return None


def load_external_csv(path: str | os.PathLike[str]) -> pd.DataFrame:
    """Load the EVTX CSV dataset into a pandas DataFrame for normalization."""
    csv_path = Path(path)
    return pd.read_csv(csv_path, low_memory=False)


def normalize_external_events(records: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize a sequence of external EVTX records into the common WinHunt schema."""
    if hasattr(records, "to_dict"):
        records = records.to_dict(orient="records")

    normalized: list[dict[str, Any]] = []
    for record in records:
        event = normalize_external_event(record)
        if event is not None:
            normalized.append(event)
    return normalized
