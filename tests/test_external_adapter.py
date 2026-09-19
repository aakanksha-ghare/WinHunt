import math
from pathlib import Path

import pandas as pd

from app.external_adapter import _as_int, load_external_csv, normalize_external_event, normalize_external_events


DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "external" / "EVTX-ATTACK-SAMPLES" / "evtx_data.csv"


def test_external_adapter_normalizes_core_supported_event_types():
    records = [
        {
            "EventID": 1,
            "SystemTime": "2024-01-01 12:00:00.000",
            "ProcessId": 123.0,
            "ProcessName": "",
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "ParentProcessId": 10,
            "ParentImage": "C:\\Windows\\System32\\services.exe",
            "CommandLine": "cmd.exe /c whoami",
            "User": "user1",
        },
        {
            "EventID": 4688,
            "SystemTime": "2024-01-01 12:01:00.000",
            "NewProcessId": "456.0",
            "NewProcessName": "C:\\Program Files\\Internet Explorer\\iexplore.exe",
            "ParentProcessId": 20,
            "ParentImage": "C:\\Windows\\explorer.exe",
            "CommandLine": "iexplore.exe https://example.com",
            "User": "user1",
        },
        {
            "EventID": 3,
            "SystemTime": "2024-01-01 12:02:00.000",
            "ProcessId": 123.0,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "DestinationIp": "8.8.8.8",
            "DestinationPort": "53",
            "Protocol": "UDP",
            "User": "user1",
        },
        {
            "EventID": 7,
            "SystemTime": "2024-01-01 12:03:00.000",
            "ProcessId": 123.0,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "ImageLoaded": "C:\\Windows\\System32\\kernel32.dll",
            "User": "user1",
        },
        {
            "EventID": 8,
            "SystemTime": "2024-01-01 12:04:00.000",
            "SourceProcessId": "300",
            "SourceImage": "C:\\Windows\\System32\\cmd.exe",
            "TargetProcessId": "301",
            "TargetImage": "C:\\Windows\\System32\\notepad.exe",
            "StartAddress": "0x12345678",
        },
        {
            "EventID": 10,
            "SystemTime": "2024-01-01 12:05:00.000",
            "SourceProcessId": 300,
            "SourceImage": "C:\\Windows\\System32\\cmd.exe",
            "TargetProcessId": 301,
            "TargetImage": "C:\\Windows\\System32\\notepad.exe",
            "GrantedAccess": "0x1F3FFF",
        },
        {
            "EventID": 11,
            "SystemTime": "2024-01-01 12:06:00.000",
            "ProcessId": 123.0,
            "Image": "C:\\Windows\\System32\\cmd.exe",
            "TargetFilename": "C:\\Temp\\demo.txt",
            "User": "user1",
        },
        {
            "EventID": 13,
            "SystemTime": "2024-01-01 12:07:00.000",
            "ProcessId": 123.0,
            "Image": "C:\\Windows\\System32\\reg.exe",
            "TargetObject": "HKLM\\Software\\Example",
            "Details": "DWORD (0x00000001)",
            "User": "user1",
        },
        {
            "EventID": 4624,
            "SystemTime": "2024-01-01 12:08:00.000",
            "TargetUserName": "user1",
            "Computer": "WKS-USER1-PC",
            "LogonType": "Interactive",
            "WorkstationName": "WKS-USER1-PC",
        },
        {
            "EventID": 4698,
            "SystemTime": "2024-01-01 12:09:00.000",
            "TaskName": "ExampleTask",
            "Action": "powershell.exe -enc AAAA",
            "Image": "C:\\Windows\\System32\\services.exe",
            "ProcessId": 700,
            "User": "SYSTEM",
            "Computer": "WKS-USER1-PC",
        },
        {
            "EventID": 7045,
            "SystemTime": "2024-01-01 12:10:00.000",
            "ServiceName": "ExampleService",
            "ImagePath": "C:\\Temp\\example.exe",
            "ServiceType": "user mode service",
            "StartType": "auto start",
            "User": "SYSTEM",
        },
    ]

    normalized = normalize_external_events(records)

    assert len(normalized) == 11
    assert {record["event_type"] for record in normalized} == {
        "process",
        "network",
        "image_load",
        "remote_thread",
        "process_access",
        "file",
        "registry",
        "logon",
        "scheduled_task",
        "service",
    }
    assert normalized[0]["process"] == "cmd.exe" and normalized[0]["pid"] == 123
    assert normalized[1]["pid"] == 456
    assert normalized[2]["dest_ip"] == "8.8.8.8"
    assert normalized[3]["image_loaded"] == "C:\\Windows\\System32\\kernel32.dll"
    assert normalized[4]["source_process"] == "cmd.exe"
    assert normalized[5]["granted_access"] == "0x1F3FFF"
    assert normalized[6]["file_path"] == "C:\\Temp\\demo.txt"
    assert normalized[7]["registry_key"] == "HKLM\\Software\\Example"
    assert normalized[8]["event_id"] == 4624
    assert normalized[8]["status"] == "success"
    assert normalized[9]["task_name"] == "ExampleTask"
    assert normalized[10]["service_name"] == "ExampleService"
    assert all("event_id" in record and "event_type" in record for record in normalized)


def test_as_int_coercion_is_conservative_and_rejects_non_integral_numbers():
    assert _as_int("0x1d4") == 468
    assert _as_int("123.0") == 123
    assert _as_int(123.0) == 123
    assert _as_int("123.5") is None
    assert _as_int(123.5) is None
    assert _as_int("bad-value") is None
    assert _as_int("") is None


def test_external_adapter_distinguishes_security_event_types():
    records = [
        {"EventID": 4624, "SystemTime": "2024-01-01 12:00:00.000", "TargetUserName": "alice", "Computer": "WKS-01", "LogonType": "Interactive", "WorkstationName": "WKS-01"},
        {"EventID": 4625, "SystemTime": "2024-01-01 12:01:00.000", "TargetUserName": "bob", "Computer": "WKS-01", "LogonType": "Interactive", "WorkstationName": "WKS-01"},
        {"EventID": 4648, "SystemTime": "2024-01-01 12:02:00.000", "TargetUserName": "alice", "Computer": "WKS-01", "LogonType": "NewCredentials", "SubjectUserName": "SYSTEM", "Result": "0x0", "Status": "success"},
        {"EventID": 4672, "SystemTime": "2024-01-01 12:03:00.000", "SubjectUserName": "admin01", "Computer": "DC-01", "PrivilegeList": "SeSecurityPrivilege", "Result": "0x0"},
        {"EventID": 4771, "SystemTime": "2024-01-01 12:04:00.000", "TargetUserName": "Administrator", "Computer": "DC-01", "ServiceName": "krbtgt/EXAMPLE.COM", "FailureReason": "PreAuthFailed"},
    ]

    normalized = normalize_external_events(records)

    assert [record["event_type"] for record in normalized] == [
        "logon",
        "logon",
        "explicit_credentials",
        "special_privileges",
        "kerberos_failure",
    ]
    assert normalized[0]["status"] == "success"
    assert normalized[1]["status"] == "failure"
    assert "status" not in normalized[2]
    assert "status" not in normalized[3]
    assert "status" not in normalized[4]
    assert normalized[2]["event_id"] == 4648
    assert normalized[3]["privilege_list"] == "SeSecurityPrivilege"
    assert normalized[4]["service_name"] == "krbtgt/EXAMPLE.COM"


def test_external_adapter_handles_missing_values_and_unsupported_events():
    records = [
        {
            "EventID": 1,
            "SystemTime": "2024-01-01 12:00:00.000",
            "ProcessId": math.nan,
            "ProcessName": math.nan,
            "Image": "C:\\Windows\\System32\\notepad.exe",
            "ParentImage": math.nan,
            "CommandLine": math.nan,
            "User": None,
        },
        {
            "EventID": 999,
            "SystemTime": "2024-01-01 12:00:00.000",
            "Message": "unsupported",
        },
    ]

    normalized = normalize_external_events(records)

    assert len(normalized) == 1
    assert normalized[0]["event_type"] == "process"
    assert normalized[0]["pid"] is None
    assert normalized[0]["process"] == "notepad.exe"
    assert normalize_external_event({"EventID": 999, "Message": "unsupported"}) is None


def test_external_adapter_handles_dataframe_input_and_pid_coercion():
    records = pd.DataFrame(
        [
            {
                "EventID": 1,
                "SystemTime": "2024-01-01 12:00:00.000",
                "ProcessId": "0x000001d4",
                "Image": "C:\\Windows\\System32\\services.exe",
                "ParentProcessId": "0x00000004",
                "ParentImage": "C:\\Windows\\System32\\wininit.exe",
                "CommandLine": "services.exe",
                "User": "SYSTEM",
            },
            {
                "EventID": 22,
                "SystemTime": "2024-01-01 12:05:00.000",
                "ProcessId": "2428",
                "Image": "C:\\Windows\\System32\\svchost.exe",
                "QueryName": "wpad",
                "QueryResults": "-",
                "User": "user1",
            },
        ]
    )

    normalized = normalize_external_events(records)

    assert len(normalized) == 2
    assert normalized[0]["pid"] == 468
    assert normalized[0]["parent_pid"] == 4
    assert normalized[1]["event_type"] == "dns"
    assert normalized[1]["query_name"] == "wpad"


def test_external_adapter_supports_real_evtx_rows_for_key_ids():
    if not DATA_PATH.exists():
        return

    df = load_external_csv(DATA_PATH)
    sample_ids = [1, 3, 7, 8, 10, 11, 13, 17, 18, 19, 20, 21, 22, 23, 4624, 4625, 4648, 4672, 4771, 4688, 4698, 4702, 7045]
    rows = []
    for event_id in sample_ids:
        matches = df[df["EventID"] == event_id]
        if not matches.empty:
            rows.append(matches.iloc[0].to_dict())

    normalized = normalize_external_events(rows)
    normalized_by_id = {record["event_id"]: record for record in normalized}

    assert 1 in normalized_by_id
    assert normalized_by_id[1]["event_type"] == "process"
    assert normalized_by_id[3]["event_type"] == "network"
    assert normalized_by_id[7]["event_type"] == "image_load"
    assert normalized_by_id[8]["event_type"] == "remote_thread"
    assert normalized_by_id[10]["event_type"] == "process_access"
    assert normalized_by_id[11]["event_type"] == "file"
    assert normalized_by_id[13]["event_type"] == "registry"
    assert normalized_by_id[17]["event_type"] == "named_pipe"
    assert normalized_by_id[18]["event_type"] == "named_pipe"
    assert normalized_by_id[19]["event_type"] == "wmi"
    assert normalized_by_id[20]["event_type"] == "wmi"
    assert normalized_by_id[21]["event_type"] == "wmi"
    assert normalized_by_id[22]["event_type"] == "dns"
    assert normalized_by_id[23]["event_type"] == "file"
    assert normalized_by_id[4624]["event_type"] == "logon"
    assert normalized_by_id[4625]["event_type"] == "logon"
    assert normalized_by_id[4648]["event_type"] == "explicit_credentials"
    assert normalized_by_id[4672]["event_type"] == "special_privileges"
    assert normalized_by_id[4771]["event_type"] == "kerberos_failure"
    assert normalized_by_id[4688]["event_type"] == "process"
    assert normalized_by_id[4698]["event_type"] == "scheduled_task"
    assert normalized_by_id[4702]["event_type"] == "scheduled_task"
    assert normalized_by_id[7045]["event_type"] == "service"


def test_external_adapter_status_semantics_for_security_events():
    records = [
        {"EventID": 4624, "TargetUserName": "alice", "Computer": "WKS-01", "LogonType": "Interactive", "WorkstationName": "WKS-01"},
        {"EventID": 4625, "TargetUserName": "bob", "Computer": "WKS-01", "LogonType": "Interactive", "WorkstationName": "WKS-01"},
        {"EventID": 4648, "TargetUserName": "alice", "Computer": "WKS-01", "LogonType": "NewCredentials", "SubjectUserName": "SYSTEM"},
        {"EventID": 4672, "SubjectUserName": "admin01", "Computer": "DC-01", "PrivilegeList": "SeSecurityPrivilege"},
        {"EventID": 4771, "TargetUserName": "Administrator", "Computer": "DC-01", "ServiceName": "krbtgt/EXAMPLE.COM"},
    ]

    normalized = normalize_external_events(records)

    assert normalized[0]["status"] == "success"
    assert normalized[1]["status"] == "failure"
    assert "status" not in normalized[2]
    assert "status" not in normalized[3]
    assert "status" not in normalized[4]
    assert normalized[2]["event_type"] == "explicit_credentials"
    assert normalized[3]["event_type"] == "special_privileges"
    assert normalized[4]["event_type"] == "kerberos_failure"


def test_external_adapter_does_not_classify_event_id_15_as_registry():
    record = {
        "EventID": 15,
        "SystemTime": "2024-01-01 12:00:00.000",
        "ProcessId": 2812,
        "Image": "C:\\Windows\\system32\\cmd.exe",
        "TargetFilename": "C:\\Users\\IEUser\\AppData",
        "User": "SYSTEM",
    }

    normalized = normalize_external_event(record)

    assert normalized is not None
    assert normalized["event_type"] == "file"
    assert normalized["event_id"] == 15
    assert normalized["file_path"] == "C:\\Users\\IEUser\\AppData"


def test_external_adapter_dataset_smoke_test_uses_real_csv_without_nan_values():
    if not DATA_PATH.exists():
        return

    df = load_external_csv(DATA_PATH)
    normalized = normalize_external_events(df)

    assert len(normalized) > 0
    assert all("event_id" in row and "event_type" in row for row in normalized)
    assert all(not any(pd.isna(value) for value in row.values() if isinstance(value, (float, int))) for row in normalized)
    assert any(row["event_id"] == 15 and row["event_type"] == "file" for row in normalized)
