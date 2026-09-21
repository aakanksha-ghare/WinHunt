import pytest

from app import detection_engine
from app.detection_engine import DETECTION_RULES, detect_event, detect_events


def test_registry_contains_exactly_the_four_existing_detectors():
    assert len(DETECTION_RULES) == 4
    assert [rule.__name__ for rule in DETECTION_RULES] == [
        "detect_encoded_powershell",
        "detect_office_to_powershell",
        "detect_suspicious_executable_location",
        "detect_scheduled_task_creation",
    ]


def test_detect_event_returns_empty_list_for_non_dict_input():
    assert detect_event(None) == []
    assert detect_event([]) == []
    assert detect_event("bad-event") == []


def test_detect_event_returns_empty_list_when_no_rule_matches():
    event = {
        "event_type": "process",
        "event_id": 99,
        "timestamp": "2026-09-15T12:00:00",
        "pid": 123,
        "process": "notepad.exe",
        "parent_process": "explorer.exe",
        "command_line": "notepad.exe",
    }

    assert detect_event(event) == []


def test_detect_event_returns_encoded_powershell_finding():
    event = {
        "event_type": "process",
        "event_id": 1,
        "timestamp": "2026-09-15T10:00:00",
        "pid": 2420,
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc AAAABBBB",
    }

    findings = detect_event(event)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "WINHUNT-001"
    assert findings[0]["severity"] == "high"
    assert findings[0]["evidence"]["command_line"] == event["command_line"]


def test_detect_event_returns_office_to_powershell_finding():
    event = {
        "event_type": "process",
        "event_id": 2,
        "timestamp": "2026-09-15T10:01:00",
        "pid": 2421,
        "process": "powershell.exe",
        "parent_process": "winword.exe",
        "command_line": "powershell.exe -Command Get-Process",
    }

    findings = detect_event(event)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "WINHUNT-002"
    assert findings[0]["severity"] == "high"
    assert findings[0]["evidence"]["parent_process"] == "winword.exe"


def test_detect_event_returns_suspicious_executable_location_finding():
    event = {
        "event_type": "process",
        "event_id": 3,
        "timestamp": "2026-09-15T10:02:00",
        "pid": 2422,
        "process": "C:\\Users\\User\\AppData\\Roaming\\backup.exe",
        "command_line": "C:\\Users\\User\\AppData\\Roaming\\backup.exe",
    }

    findings = detect_event(event)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "WINHUNT-003"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["evidence"]["location"] == "AppData"


def test_detect_event_returns_scheduled_task_creation_finding():
    event = {
        "event_type": "scheduled_task",
        "event_id": 4698,
        "timestamp": "2026-09-15T09:00:00.408Z",
        "task_name": "GoogleUpdateTaskMachineCore",
        "action": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c",
        "created_by_process": "services.exe",
        "created_by_pid": 700,
        "user": "SYSTEM",
        "host": "WKS-USER1-PC",
    }

    findings = detect_event(event)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "WINHUNT-004"
    assert findings[0]["rule_name"] == "Scheduled Task Created"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["evidence"]["task_name"] == "GoogleUpdateTaskMachineCore"


def test_detect_event_returns_multiple_findings_for_single_event():
    event = {
        "event_type": "process",
        "event_id": 4,
        "timestamp": "2026-09-15T10:03:00",
        "pid": 2423,
        "process": "C:\\Users\\User\\AppData\\Roaming\\powershell.exe",
        "parent_process": "winword.exe",
        "command_line": "C:\\Users\\User\\AppData\\Roaming\\powershell.exe -enc AAAABBBB",
    }

    findings = detect_event(event)

    assert [finding["rule_id"] for finding in findings] == [
        "WINHUNT-001",
        "WINHUNT-002",
        "WINHUNT-003",
    ]


def test_detect_events_flattens_findings_in_event_order():
    events = [
        {
            "event_type": "process",
            "event_id": 1,
            "timestamp": "2026-09-15T10:00:00",
            "pid": 2420,
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc AAAABBBB",
        },
        {
            "event_type": "process",
            "event_id": 2,
            "timestamp": "2026-09-15T10:01:00",
            "pid": 2421,
            "process": "powershell.exe",
            "parent_process": "winword.exe",
            "command_line": "powershell.exe -Command Get-Process",
        },
    ]

    findings = detect_events(events)

    assert [finding["rule_id"] for finding in findings] == ["WINHUNT-001", "WINHUNT-002"]
    assert [finding["event_id"] for finding in findings] == [1, 2]


def test_detect_events_preserves_rule_order_and_event_order():
    events = [
        {
            "event_type": "process",
            "event_id": 10,
            "timestamp": "2026-09-15T10:10:00",
            "pid": 1110,
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc AAAABBBB",
        },
        {
            "event_type": "scheduled_task",
            "event_id": 4698,
            "timestamp": "2026-09-15T10:11:00",
            "task_name": "ExampleTask",
            "action": "powershell.exe -enc AAAA",
            "created_by_process": "services.exe",
            "created_by_pid": 700,
            "user": "SYSTEM",
            "host": "host1",
        },
    ]

    findings = detect_events(events)

    assert [finding["rule_id"] for finding in findings] == ["WINHUNT-001", "WINHUNT-004"]
    assert [finding["event_id"] for finding in findings] == [10, 4698]


def test_detect_event_does_not_mutate_input_event():
    event = {
        "event_type": "process",
        "event_id": 5,
        "timestamp": "2026-09-15T10:05:00",
        "pid": 2425,
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc AAAABBBB",
    }

    original = {
        "event_type": event["event_type"],
        "event_id": event["event_id"],
        "timestamp": event["timestamp"],
        "pid": event["pid"],
        "process": event["process"],
        "command_line": event["command_line"],
    }

    detect_event(event)

    assert event == original


def test_detect_event_preserves_finding_objects_exactly():
    event = {
        "event_type": "scheduled_task",
        "event_id": 4698,
        "timestamp": "2026-09-15T09:00:00.408Z",
        "task_name": "GoogleUpdateTaskMachineCore",
        "action": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c",
        "created_by_process": "services.exe",
        "created_by_pid": 700,
        "user": "SYSTEM",
        "host": "WKS-USER1-PC",
    }

    findings = detect_event(event)

    assert findings[0] == {
        "rule_id": "WINHUNT-004",
        "rule_name": "Scheduled Task Created",
        "severity": "medium",
        "timestamp": event["timestamp"],
        "event_id": event["event_id"],
        "event_type": event["event_type"],
        "pid": event.get("pid"),
        "process": event.get("process"),
        "reason": "A scheduled task was created, which may indicate persistence and warrants investigation.",
        "evidence": {
            "task_name": "GoogleUpdateTaskMachineCore",
            "action": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c",
            "created_by_process": "services.exe",
            "created_by_pid": 700,
            "user": "SYSTEM",
            "host": "WKS-USER1-PC",
        },
    }


def test_detect_event_ignores_rule_result_of_none():
    custom_rules = [
        lambda event: None,
        lambda event: {"rule_id": "WINHUNT-001", "severity": "high"},
    ]

    original_rules = detection_engine.DETECTION_RULES
    try:
        detection_engine.DETECTION_RULES = custom_rules
        assert detect_event({"event_type": "process"}) == [{"rule_id": "WINHUNT-001", "severity": "high"}]
    finally:
        detection_engine.DETECTION_RULES = original_rules


def test_detect_event_does_not_silently_swallow_rule_exception():
    def bad_rule(event):
        raise ValueError("rule failure")

    original_rules = detection_engine.DETECTION_RULES
    try:
        detection_engine.DETECTION_RULES = [bad_rule]
        with pytest.raises(ValueError, match="rule failure"):
            detect_event({"event_type": "process", "process": "powershell.exe"})
    finally:
        detection_engine.DETECTION_RULES = original_rules


def test_detect_events_returns_empty_list_for_empty_input():
    assert detect_events([]) == []
    assert detect_events(()) == []
    assert detect_events(iter(())) == []
