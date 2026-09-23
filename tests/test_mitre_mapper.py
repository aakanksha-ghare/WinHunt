import copy
import json

from app.mitre_mapper import map_chain, map_finding, map_findings


def get_ids(result):
    return [item["technique_id"] for item in result["mitre"]]


# -------------------------
# Basic / empty input
# -------------------------

def test_none_finding():
    assert map_finding(None) == {"mitre": []}


def test_malformed_finding():
    assert map_finding("not a finding") == {"mitre": []}


def test_empty_finding():
    assert map_finding({}) == {"mitre": []}


# -------------------------
# Explicit finding mappings
# -------------------------

def test_encoded_powershell():
    finding = {
        "finding_type": "encoded_powershell",
        "evidence": {
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc abc",
        },
    }

    result = map_finding(finding)

    assert "T1059.001" in get_ids(result)


def test_office_to_powershell():
    finding = {
        "finding_type": "office_to_powershell",
        "evidence": {
            "process": "powershell.exe",
            "parent_process": "winword.exe",
        },
    }

    result = map_finding(finding)

    assert "T1059.001" in get_ids(result)


def test_scheduled_task_creation():
    finding = {
        "finding_type": "scheduled_task_creation",
        "evidence": {"task_name": "UpdateTask"},
    }

    result = map_finding(finding)

    assert "T1053.005" in get_ids(result)


def test_registry_run_key_persistence():
    finding = {
        "finding_type": "registry_run_key_persistence",
        "evidence": {
            "registry_path": (
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
            )
        },
    }

    result = map_finding(finding)

    assert "T1547.001" in get_ids(result)


def test_startup_persistence():
    finding = {
        "finding_type": "startup_persistence",
        "evidence": {
            "path": (
                r"C:\Users\alice\AppData\Roaming\Microsoft\Windows"
                r"\Start Menu\Programs\Startup\evil.lnk"
            )
        },
    }

    result = map_finding(finding)

    assert "T1547.001" in get_ids(result)


def test_service_installation():
    finding = {
        "finding_type": "service_installation",
        "evidence": {"service_name": "SuspiciousService"},
    }

    result = map_finding(finding)

    assert "T1569.002" in get_ids(result)


def test_new_account():
    finding = {
        "finding_type": "new_account",
        "evidence": {"new_account": "testuser"},
    }

    result = map_finding(finding)

    assert "T1136.001" in get_ids(result)


def test_failed_login_burst():
    finding = {
        "finding_type": "failed_login_burst",
        "evidence": {"failure_count": 7},
    }

    result = map_finding(finding)

    assert "T1110.001" in get_ids(result)


# -------------------------
# Conservative mappings
# -------------------------

def test_generic_scheduled_task_is_not_mapped():
    finding = {
        "finding_type": "scheduled_task",
        "evidence": {"task_name": "Update"},
    }

    assert get_ids(map_finding(finding)) == []


def test_generic_powershell_is_not_mapped():
    finding = {
        "finding_type": "Power_Shell",
        "evidence": {
            "command_line": "powershell.exe -NoLogo"
        },
    }

    assert get_ids(map_finding(finding)) == []


def test_generic_wmi_activity_is_not_mapped():
    finding = {
        "finding_type": "custom",
        "evidence": {
            "event_type": "wmi",
            "description": "WMI activity observed",
        },
    }

    assert get_ids(map_finding(finding)) == []


# -------------------------
# Process injection
# -------------------------

def test_explicit_process_injection():
    finding = {
        "finding_type": "process_injection",
        "evidence": {
            "description": "Process injection observed",
        },
    }

    result = map_finding(finding)

    assert "T1055" in get_ids(result)


def test_process_access_and_remote_thread():
    finding = {
        "finding_type": "custom",
        "evidence": {
            "event_ids": [10, 8],
            "process_access": "yes",
            "create_remote_thread": "yes",
        },
    }

    result = map_finding(finding)

    assert "T1055" in get_ids(result)


def test_remote_thread_alone_is_not_process_injection():
    finding = {
        "finding_type": "custom",
        "evidence": {
            "reason": "remote thread occurred",
        },
    }

    assert get_ids(map_finding(finding)) == []


def test_process_access_alone_is_not_process_injection():
    finding = {
        "finding_type": "custom",
        "evidence": {
            "process_access": "yes",
        },
    }

    assert get_ids(map_finding(finding)) == []


def test_event_8_alone_is_not_process_injection():
    finding = {
        "finding_type": "custom",
        "evidence": {
            "event_id": 8,
        },
    }

    assert get_ids(map_finding(finding)) == []


# -------------------------
# WMI event subscription
# -------------------------

def test_wmi_event_subscription():
    finding = {
        "finding_type": "wmi_event_subscription",
        "evidence": {
            "subscription_name": "SuspiciousSubscription",
            "query": "SELECT * FROM __InstanceCreationEvent",
        },
    }

    result = map_finding(finding)

    assert "T1546.003" in get_ids(result)


# -------------------------
# Metadata correctness
# -------------------------

def test_power_shell_metadata():
    result = map_finding(
        {
            "finding_type": "encoded_powershell",
            "evidence": {
                "process": "powershell.exe",
                "command_line": "powershell.exe -enc abc",
            },
        }
    )

    entry = next(
        item for item in result["mitre"]
        if item["technique_id"] == "T1059.001"
    )

    assert entry["technique_name"] == (
        "Command and Scripting Interpreter: PowerShell"
    )
    assert entry["tactic"] == "Execution"
    assert entry["source"] == "WinHunt detection mapping"


def test_scheduled_task_has_expected_tactics():
    result = map_finding(
        {
            "finding_type": "scheduled_task_creation",
            "evidence": {"task_name": "Task"},
        }
    )

    entries = [
        item
        for item in result["mitre"]
        if item["technique_id"] == "T1053.005"
    ]

    assert {item["tactic"] for item in entries} == {
        "Execution",
        "Persistence",
        "Privilege Escalation",
    }


# -------------------------
# Top-level / evidence precedence
# -------------------------

def test_top_level_finding_type_takes_precedence():
    finding = {
        "finding_type": "encoded_powershell",
        "evidence": {
            "finding_type": "scheduled_task_creation",
        },
    }

    result = map_finding(finding)

    assert "T1059.001" in get_ids(result)
    assert "T1053.005" not in get_ids(result)


def test_top_level_process_fields_are_used():
    finding = {
        "finding_type": "custom",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc abc",
        "evidence": {
            "process": "notepad.exe",
            "command_line": "notepad.exe",
        },
    }

    result = map_finding(finding)

    assert "T1059.001" in get_ids(result)


# -------------------------
# Existing MITRE entries
# -------------------------

def test_existing_mitre_entries_are_preserved():
    finding = {
        "finding_type": "encoded_powershell",
        "evidence": {
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc abc",
        },
        "mitre": [
            {
                "technique_id": "T9999",
                "technique_name": "Existing Technique",
                "tactic": "Test",
                "source": "Existing source",
            }
        ],
    }

    result = map_finding(finding)

    assert "T9999" in get_ids(result)
    assert "T1059.001" in get_ids(result)


def test_duplicate_mitre_entries_are_removed():
    finding = {
        "finding_type": "encoded_powershell",
        "evidence": {
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc abc",
        },
        "mitre": [
            {
                "technique_id": "T1059.001",
                "technique_name": (
                    "Command and Scripting Interpreter: PowerShell"
                ),
                "tactic": "Execution",
                "source": "Existing source",
            },
            {
                "technique_id": "T1059.001",
                "technique_name": (
                    "Command and Scripting Interpreter: PowerShell"
                ),
                "tactic": "Execution",
                "source": "Existing source",
            },
        ],
    }

    result = map_finding(finding)

    matching = [
        item
        for item in result["mitre"]
        if item["technique_id"] == "T1059.001"
        and item["tactic"] == "Execution"
    ]

    assert len(matching) == 1


# -------------------------
# Immutability
# -------------------------

def test_map_finding_does_not_mutate_input():
    finding = {
        "finding_type": "encoded_powershell",
        "evidence": {
            "process": "powershell.exe",
            "command_line": "powershell.exe -enc abc",
        },
    }

    original = copy.deepcopy(finding)

    result = map_finding(finding)

    assert finding == original
    assert "mitre" not in finding
    assert result is not finding


def test_nested_input_is_deep_copied():
    finding = {
        "finding_type": "encoded_powershell",
        "evidence": {
            "command_line": "powershell.exe -enc abc",
            "nested": {"value": ["original"]},
        },
    }

    result = map_finding(finding)

    result["evidence"]["nested"]["value"].append("changed")

    assert finding["evidence"]["nested"]["value"] == ["original"]


# -------------------------
# Lists
# -------------------------

def test_map_findings_preserves_order():
    findings = [
        {"finding_type": "encoded_powershell"},
        {"finding_type": "service_installation"},
        {"finding_type": "new_account"},
    ]

    result = map_findings(findings)

    assert len(result) == 3
    assert result[0]["finding_type"] == "encoded_powershell"
    assert result[1]["finding_type"] == "service_installation"
    assert result[2]["finding_type"] == "new_account"


def test_map_findings_does_not_mutate_input():
    findings = [
        {
            "finding_type": "encoded_powershell",
            "evidence": {
                "process": "powershell.exe",
                "command_line": "powershell.exe -enc abc",
            },
        }
    ]

    original = copy.deepcopy(findings)

    result = map_findings(findings)

    assert findings == original
    assert "mitre" not in findings[0]
    assert "T1059.001" in get_ids(result[0])


# -------------------------
# Chain mapping
# -------------------------

def test_map_chain_preserves_core_fields():
    chain = {
        "chain_id": "CHAIN-001",
        "finding_count": 2,
        "start_time": "2026-09-15T10:00:00Z",
        "end_time": "2026-09-15T10:10:00Z",
        "duration_seconds": 600,
        "host": "WIN-CLIENT-01",
        "users": ["alice"],
        "risk_score": 85,
        "risk_level": "critical",
        "risk_factors": ["encoded_powershell"],
        "correlation_reasons": ["shared_pid"],
        "findings": [
            {
                "finding_type": "encoded_powershell",
                "evidence": {
                    "process": "powershell.exe",
                    "command_line": "powershell.exe -enc abc",
                },
            },
            {
                "finding_type": "service_installation",
                "evidence": {"service_name": "svc"},
            },
        ],
    }

    original = copy.deepcopy(chain)
    result = map_chain(chain)

    assert result["chain_id"] == original["chain_id"]
    assert result["finding_count"] == original["finding_count"]
    assert result["start_time"] == original["start_time"]
    assert result["end_time"] == original["end_time"]
    assert result["duration_seconds"] == original["duration_seconds"]
    assert result["host"] == original["host"]
    assert result["users"] == original["users"]
    assert result["risk_score"] == original["risk_score"]
    assert result["risk_level"] == original["risk_level"]
    assert result["risk_factors"] == original["risk_factors"]
    assert result["correlation_reasons"] == original["correlation_reasons"]

    assert "T1059.001" in get_ids(result["findings"][0])
    assert "T1569.002" in get_ids(result["findings"][1])
    assert "T1059.001" in get_ids(result)
    assert "T1569.002" in get_ids(result)


def test_map_chain_does_not_mutate_input():
    chain = {
        "finding_count": 1,
        "risk_score": 70,
        "findings": [
            {
                "finding_type": "encoded_powershell",
                "evidence": {
                    "process": "powershell.exe",
                    "command_line": "powershell.exe -enc abc",
                },
            }
        ],
    }

    original = copy.deepcopy(chain)

    result = map_chain(chain)

    assert chain == original
    assert "mitre" not in chain["findings"][0]
    assert "T1059.001" in get_ids(result["findings"][0])


# -------------------------
# Serialization / determinism
# -------------------------

def test_mapper_output_is_json_serializable():
    finding = {
        "finding_type": "scheduled_task_creation",
        "evidence": {"task_name": "Task"},
    }

    result = map_finding(finding)

    json.dumps(result)


def test_mapping_is_deterministic():
    finding = {
        "finding_type": "scheduled_task_creation",
        "evidence": {"task_name": "Task"},
    }

    first = map_finding(finding)
    second = map_finding(finding)

    assert first == second


def test_mitre_entries_are_sorted_deterministically():
    finding = {
        "finding_type": "scheduled_task_creation",
        "evidence": {"task_name": "Task"},
    }

    result = map_finding(finding)

    keys = [
        (
            item["technique_id"],
            item["tactic"],
            item["technique_name"],
        )
        for item in result["mitre"]
    ]

    assert keys == sorted(keys)