import copy
import json
from pathlib import Path

from app.parser import (
    normalize_file_event,
    normalize_logon_event,
    normalize_network_event,
    normalize_process_event,
    normalize_scheduled_task_event,
    parse_events,
    parse_process_events,
)


DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_events.json"


def test_parse_process_events_returns_all_process_creation_records():
    with DATA_PATH.open("r", encoding="utf-8") as handle:
        events = json.load(handle)

    parsed = parse_process_events(events)
    raw_process_events = [event for event in events if event["event_id"] == 1]

    assert len(parsed) == 665
    assert len(raw_process_events) == 665
    assert len(parsed) == len(raw_process_events)

    required_fields = {
        "timestamp",
        "pid",
        "process",
        "parent_pid",
        "parent_process",
        "command_line",
        "user",
        "path",
    }

    for record in parsed:
        assert required_fields.issubset(record)
        assert record["timestamp"]
        assert record["process"]
        assert record["pid"]

    assert {record["pid"] for record in parsed} == {event["pid"] for event in raw_process_events}
    assert {record["process"] for record in parsed} == {event["process"] for event in raw_process_events}


def test_parse_events_parses_all_supported_event_types_and_preserves_order():
    with DATA_PATH.open("r", encoding="utf-8") as handle:
        events = json.load(handle)

    parsed = parse_events(events)

    expected_counts = {
        "process": 665,
        "network": 230,
        "file": 141,
        "logon": 18,
        "scheduled_task": 6,
    }

    assert len(parsed) == 1060
    assert len(parsed) == sum(expected_counts.values())
    assert {record["event_type"] for record in parsed} == set(expected_counts)

    for event_type, count in expected_counts.items():
        assert sum(1 for record in parsed if record["event_type"] == event_type) == count

    assert [record["event_type"] for record in parsed[:5]] == ["process", "process", "process", "process", "logon"]
    assert [event["event_id"] for event in events if event["event_id"] in {1, 3, 11, 4624, 4625, 4698}][:5] == [1, 1, 1, 1, 4624]


def test_normalize_process_event_returns_expected_fields():
    sample_event = {
        "event_id": 1,
        "timestamp": "2026-09-15T08:05:00.754Z",
        "process": "chrome.exe",
        "pid": 2020,
        "parent_process": "explorer.exe",
        "parent_pid": 2012,
        "command_line": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"",
        "user": "user1",
        "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    }

    normalized = normalize_process_event(sample_event)

    assert normalized == {
        "timestamp": "2026-09-15T08:05:00.754Z",
        "pid": 2020,
        "process": "chrome.exe",
        "parent_pid": 2012,
        "parent_process": "explorer.exe",
        "command_line": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"",
        "user": "user1",
        "path": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    }


def test_normalize_network_event_returns_expected_fields():
    sample_event = {
        "event_id": 3,
        "timestamp": "2026-09-15T08:05:10.095Z",
        "process": "chrome.exe",
        "pid": 2040,
        "dest_ip": "198.51.100.22",
        "dest_port": 443,
        "dest_domain": "mail.example-corp.local",
        "protocol": "TCP",
        "user": "user1",
    }

    normalized = normalize_network_event(sample_event)

    assert normalized == {
        "timestamp": "2026-09-15T08:05:10.095Z",
        "pid": 2040,
        "process": "chrome.exe",
        "dest_ip": "198.51.100.22",
        "dest_port": 443,
        "dest_domain": "mail.example-corp.local",
        "protocol": "TCP",
        "user": "user1",
    }


def test_normalize_file_event_returns_expected_fields():
    sample_event = {
        "event_id": 11,
        "timestamp": "2026-09-15T08:08:31.348Z",
        "action": "created",
        "file_path": "C:\\Users\\user1\\Documents\\todo.txt",
        "process": "notepad.exe",
        "pid": 2068,
        "user": "user1",
    }

    normalized = normalize_file_event(sample_event)

    assert normalized == {
        "timestamp": "2026-09-15T08:08:31.348Z",
        "pid": 2068,
        "process": "notepad.exe",
        "action": "created",
        "file_path": "C:\\Users\\user1\\Documents\\todo.txt",
        "user": "user1",
    }


def test_normalize_logon_event_returns_expected_fields_for_success_and_failure():
    success_event = {
        "event_id": 4624,
        "timestamp": "2026-09-15T07:58:08.228Z",
        "user": "user1",
        "source": "WKS-USER1-PC",
        "status": "success",
        "logon_type": "Interactive",
        "host": "WKS-USER1-PC",
    }
    failure_event = {
        "event_id": 4625,
        "timestamp": "2026-09-15T09:02:37.175Z",
        "user": "user1",
        "source": "WKS-USER1-PC",
        "status": "failure",
        "logon_type": "Unlock",
        "host": "WKS-USER1-PC",
    }

    assert normalize_logon_event(success_event) == {
        "timestamp": "2026-09-15T07:58:08.228Z",
        "event_id": 4624,
        "user": "user1",
        "source": "WKS-USER1-PC",
        "status": "success",
        "logon_type": "Interactive",
        "host": "WKS-USER1-PC",
    }
    assert normalize_logon_event(failure_event) == {
        "timestamp": "2026-09-15T09:02:37.175Z",
        "event_id": 4625,
        "user": "user1",
        "source": "WKS-USER1-PC",
        "status": "failure",
        "logon_type": "Unlock",
        "host": "WKS-USER1-PC",
    }


def test_normalize_scheduled_task_event_returns_expected_fields():
    sample_event = {
        "event_id": 4698,
        "timestamp": "2026-09-15T09:00:00.408Z",
        "task_name": "GoogleUpdateTaskMachineCore",
        "action": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c",
        "created_by_process": "services.exe",
        "created_by_pid": 700,
        "user": "SYSTEM",
        "host": "WKS-USER1-PC",
    }

    normalized = normalize_scheduled_task_event(sample_event)

    assert normalized == {
        "timestamp": "2026-09-15T09:00:00.408Z",
        "event_id": 4698,
        "task_name": "GoogleUpdateTaskMachineCore",
        "action": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c",
        "created_by_process": "services.exe",
        "created_by_pid": 700,
        "user": "SYSTEM",
        "host": "WKS-USER1-PC",
    }


def test_parse_events_skips_unsupported_ids_and_does_not_modify_input():
    with DATA_PATH.open("r", encoding="utf-8") as handle:
        events = json.load(handle)

    original_copy = copy.deepcopy(events)
    parsed = parse_events([{"event_id": 999, "value": "unsupported"}, *events])
    expected_supported_events = [event for event in events if event["event_id"] in {1, 3, 11, 4624, 4625, 4698}]

    assert len(parsed) == len(expected_supported_events)
    assert parsed[0]["event_type"] == "process"
    assert events == original_copy

    for record in parsed:
        assert record["event_type"] in {"process", "network", "file", "logon", "scheduled_task"}
