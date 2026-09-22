import copy
import json

from app.auth_persistence_hunter import (
    AuthPersistenceHunter,
    _looks_like_run_key,
)


def event(event_id, timestamp="2026-09-15T10:00:00Z", **kwargs):
    return {
        "event_id": event_id,
        "timestamp": timestamp,
        **kwargs,
    }


def test_run_key_exact_and_value_paths():
    positives = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
        r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce\MyValue",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Example",
    ]

    negatives = [
        r"C:\Temp\run_command.bat",
        r"HKCU\Software\Something\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunStuff",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Startup",
    ]

    assert all(_looks_like_run_key(value) for value in positives)
    assert all(not _looks_like_run_key(value) for value in negatives)


def test_failed_login_burst():
    events = [
        event(
            4625,
            f"2026-09-15T10:0{i}:00Z",
            user="alice",
            host="WIN-CLIENT-01",
            source_ip="10.0.0.50",
        )
        for i in range(5)
    ]

    findings = AuthPersistenceHunter(events).detect_failed_login_bursts()

    assert len(findings) == 1
    finding = findings[0]
    assert finding["finding_type"] == "failed_login_burst"
    assert finding["severity"] == "medium"
    assert finding["evidence"]["failure_count"] == 5


def test_failure_then_success():
    events = [
        event(4625, "2026-09-15T10:00:00Z", user="alice", host="WIN-01"),
        event(4625, "2026-09-15T10:02:00Z", user="alice", host="WIN-01"),
        event(4625, "2026-09-15T10:04:00Z", user="alice", host="WIN-01"),
        event(4624, "2026-09-15T10:05:00Z", user="alice", host="WIN-01"),
    ]

    findings = AuthPersistenceHunter(events).detect_failure_then_success()

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "failure_then_success"
    assert findings[0]["evidence"]["failure_count"] == 3


def test_explicit_credentials():
    events = [
        event(
            4648,
            user="alice",
            target_user="admin",
            target_host="SERVER-01",
            process="powershell.exe",
            command_line="powershell.exe -Command whoami",
            host="WIN-01",
        )
    ]

    findings = AuthPersistenceHunter(events).detect_explicit_credentials()

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "explicit_credential_use"
    assert findings[0]["evidence"]["target_user"] == "admin"


def test_privileged_logon():
    events = [
        event(
            4672,
            user="admin",
            host="WIN-ADMIN-01",
            privileges=["SeDebugPrivilege"],
        )
    ]

    findings = AuthPersistenceHunter(events).detect_privileged_logons()

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "privileged_logon"
    assert findings[0]["user"] == "admin"


def test_account_lockout():
    events = [
        event(
            4740,
            target_user="bob",
            host="WIN-DC-01",
            source_workstation="WIN-CLIENT-02",
        )
    ]

    findings = AuthPersistenceHunter(events).detect_account_lockouts()

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "account_lockout"
    assert findings[0]["evidence"]["account"] == "bob"


def test_new_account():
    events = [
        event(
            4720,
            user="admin",
            target_user="eviluser",
            host="WIN-ADMIN-01",
        )
    ]

    findings = AuthPersistenceHunter(events).detect_new_accounts()

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "new_account_created"
    assert findings[0]["evidence"]["new_account"] == "eviluser"
    assert findings[0]["evidence"]["creator"] == "admin"


def test_local_group_membership_change():
    events = [
        event(
            4732,
            user="admin",
            member_name="eviluser",
            target_group="Administrators",
            host="WIN-ADMIN-01",
        )
    ]

    findings = AuthPersistenceHunter(events).detect_local_group_membership_changes()

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "local_group_membership_change"
    assert findings[0]["evidence"]["member"] == "eviluser"
    assert findings[0]["evidence"]["group"] == "Administrators"


def test_scheduled_task_persistence():
    events = [
        event(
            4698,
            user="alice",
            host="WIN-CLIENT-01",
            task_name="Updater",
            action=r"C:\Users\alice\AppData\Roaming\updater.exe",
        )
    ]

    findings = AuthPersistenceHunter(events).detect_scheduled_task_persistence()

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "scheduled_task_persistence"
    assert findings[0]["evidence"]["task_name"] == "Updater"


def test_registry_run_key_persistence_from_exact_key():
    events = [
        event(
            13,
            user="alice",
            host="WIN-CLIENT-01",
            registry_key=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            value_name="Updater",
            value_data=r"C:\Users\alice\AppData\Roaming\updater.exe",
        )
    ]

    findings = AuthPersistenceHunter(events).detect_registry_run_key_persistence()

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "registry_run_key_persistence"
    assert findings[0]["evidence"]["value_name"] == "Updater"


def test_registry_run_key_persistence_from_value_path():
    events = [
        event(
            13,
            user="alice",
            host="WIN-CLIENT-01",
            target_object=(
                r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater"
            ),
            value_data=r"C:\Users\alice\AppData\Roaming\updater.exe",
        )
    ]

    findings = AuthPersistenceHunter(events).detect_registry_run_key_persistence()

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "registry_run_key_persistence"


def test_non_run_registry_path_is_ignored():
    events = [
        event(
            13,
            user="alice",
            host="WIN-CLIENT-01",
            target_object=r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunStuff",
            value_name="Updater",
        ),
        event(
            13,
            user="alice",
            host="WIN-CLIENT-01",
            target_object=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Startup",
            value_name="Updater",
        ),
    ]

    findings = AuthPersistenceHunter(events).detect_registry_run_key_persistence()

    assert findings == []


def test_startup_persistence():
    events = [
        event(
            11,
            user="alice",
            host="WIN-CLIENT-01",
            path=(
                r"C:\Users\alice\AppData\Roaming\Microsoft\Windows"
                r"\Start Menu\Programs\Startup\updater.exe"
            ),
        )
    ]

    findings = AuthPersistenceHunter(events).detect_startup_persistence()

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "startup_persistence"


def test_service_installation():
    events = [
        event(
            7045,
            user="admin",
            host="WIN-ADMIN-01",
            service_name="MaliciousService",
            image=r"C:\Windows\System32\malicious.exe",
            service_account="LocalSystem",
        )
    ]

    findings = AuthPersistenceHunter(events).detect_service_installation()

    assert len(findings) == 1
    assert findings[0]["finding_type"] == "service_installation"
    assert findings[0]["severity"] == "high"


def test_all_required_detectors_produce_findings():
    events = [
        # Failed-login burst
        event(4625, "2026-09-15T10:00:00Z", user="alice", host="WIN-01"),
        event(4625, "2026-09-15T10:01:00Z", user="alice", host="WIN-01"),
        event(4625, "2026-09-15T10:02:00Z", user="alice", host="WIN-01"),
        event(4625, "2026-09-15T10:03:00Z", user="alice", host="WIN-01"),
        event(4625, "2026-09-15T10:04:00Z", user="alice", host="WIN-01"),

        # Failure -> success
        event(4625, "2026-09-15T11:00:00Z", user="bob", host="WIN-02"),
        event(4625, "2026-09-15T11:02:00Z", user="bob", host="WIN-02"),
        event(4625, "2026-09-15T11:04:00Z", user="bob", host="WIN-02"),
        event(4624, "2026-09-15T11:05:00Z", user="bob", host="WIN-02"),

        event(4648, user="alice", target_user="admin", host="WIN-01"),
        event(4672, user="admin", host="WIN-ADMIN-01"),
        event(4740, target_user="bob", host="WIN-02"),
        event(4720, user="admin", target_user="eviluser", host="WIN-ADMIN-01"),
        event(
            4732,
            user="admin",
            member_name="eviluser",
            target_group="Administrators",
            host="WIN-ADMIN-01",
        ),
        event(
            4698,
            user="alice",
            host="WIN-01",
            task_name="Updater",
            action=r"C:\Temp\updater.exe",
        ),
        event(
            13,
            user="alice",
            host="WIN-01",
            target_object=(
                r"HKCU\Software\Microsoft\Windows\CurrentVersion"
                r"\Run\Updater"
            ),
            value_data=r"C:\Temp\updater.exe",
        ),
        event(
            11,
            user="alice",
            host="WIN-01",
            path=(
                r"C:\Users\alice\AppData\Roaming\Microsoft\Windows"
                r"\Start Menu\Programs\Startup\updater.exe"
            ),
        ),
        event(
            7045,
            user="admin",
            host="WIN-ADMIN-01",
            service_name="MaliciousService",
            image=r"C:\Windows\System32\malicious.exe",
        ),
    ]

    findings = AuthPersistenceHunter(events).analyze()
    finding_types = {finding["finding_type"] for finding in findings}

    required_types = {
        "failed_login_burst",
        "failure_then_success",
        "explicit_credential_use",
        "privileged_logon",
        "account_lockout",
        "new_account_created",
        "local_group_membership_change",
        "scheduled_task_persistence",
        "registry_run_key_persistence",
        "startup_persistence",
        "service_installation",
    }

    assert required_types.issubset(finding_types)


def test_analyze_is_deterministic():
    events = [
        event(
            7045,
            user="admin",
            host="WIN-01",
            service_name="TestService",
            image=r"C:\Windows\System32\test.exe",
        ),
        event(
            4720,
            user="admin",
            target_user="newuser",
            host="WIN-01",
        ),
    ]

    hunter = AuthPersistenceHunter(events)

    first = hunter.analyze()
    second = hunter.analyze()

    assert first == second


def test_input_is_not_mutated():
    events = [
        event(
            13,
            user="alice",
            host="WIN-01",
            target_object=(
                r"HKCU\Software\Microsoft\Windows\CurrentVersion"
                r"\Run\Updater"
            ),
            value_name="Updater",
            value_data=r"C:\Temp\updater.exe",
            nested={"example": ["value"]},
        )
    ]

    before = copy.deepcopy(events)

    hunter = AuthPersistenceHunter(events)
    hunter.analyze()

    assert events == before


def test_findings_are_json_serializable():
    events = [
        event(
            7045,
            user="admin",
            host="WIN-01",
            service_name="TestService",
            image=r"C:\Windows\System32\test.exe",
        )
    ]

    findings = AuthPersistenceHunter(events).analyze()

    json.dumps(findings)


def test_malformed_input_is_safe():
    assert AuthPersistenceHunter(None).analyze() == []
    assert AuthPersistenceHunter([None, "bad", 123, {}]).analyze() == []