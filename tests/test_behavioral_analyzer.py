import copy
import json
from datetime import datetime, timedelta, timezone

import pytest

from app.behavioral_analyzer import BehavioralAnalyzer


@pytest.fixture
def minimal_process_event():
    return {
        "event_type": "process",
        "event_id": 1,
        "timestamp": "2026-09-15T12:00:00Z",
        "pid": 101,
        "user": "Alice",
        "host": "WIN-CLIENT-01",
        "process": "notepad.exe",
        "parent_process": "explorer.exe",
        "command_line": "notepad.exe",
    }


@pytest.fixture
def real_behavioral_dataset():
    with open("data/behavioral_history.json", "r", encoding="utf-8") as handle:
        return json.load(handle)


def isoformat_utc(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(
    *,
    timestamp: datetime,
    user: str = "Alice",
    host: str = "WIN-CLIENT-01",
    process: str = "notepad.exe",
    parent_process: str | None = None,
    command_line: str | None = None,
    event_type: str = "process",
    event_uid: str | None = None,
) -> dict:
    return {
        "event_type": event_type,
        "event_uid": event_uid or f"EVT-{timestamp.strftime('%Y%m%d%H%M%S')}-{process}",
        "timestamp": isoformat_utc(timestamp),
        "user": user,
        "host": host,
        "process": process,
        "parent_process": parent_process,
        "command_line": command_line or process,
    }


def test_empty_input_returns_empty_findings():
    analyzer = BehavioralAnalyzer([])
    assert analyzer.analyze() == []


def test_minimal_valid_event_constructs_successfully(minimal_process_event):
    analyzer = BehavioralAnalyzer([minimal_process_event])
    assert analyzer.events == [minimal_process_event]
    assert analyzer._dataset_start is not None
    assert analyzer._dataset_end is not None
    assert analyzer._observation_cutoff is not None


def test_invalid_timestamps_do_not_crash_and_are_ignored():
    events = [
        {"event_type": "process", "timestamp": "bad-timestamp", "user": "Alice", "host": "WIN-CLIENT-01", "process": "notepad.exe"},
        {"event_type": "process", "timestamp": "2026-09-15T12:00:00Z", "user": "Alice", "host": "WIN-CLIENT-01", "process": "calc.exe"},
    ]

    analyzer = BehavioralAnalyzer(events)
    assert analyzer.analyze() is not None


def test_timezone_normalization_keeps_equivalent_timestamps_consistent():
    dt = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(timestamp=dt, process="notepad.exe", event_uid="A"),
        make_event(timestamp=dt + timedelta(minutes=5), process="calc.exe", event_uid="B"),
        {
            "event_type": "process",
            "event_uid": "C",
            "timestamp": "2026-09-15T12:00:00+00:00",
            "user": "Alice",
            "host": "WIN-CLIENT-01",
            "process": "chrome.exe",
            "command_line": "chrome.exe",
        },
    ]

    analyzer = BehavioralAnalyzer(events)
    assert analyzer._parse_timestamp(events[0]["timestamp"]) == analyzer._parse_timestamp(events[2]["timestamp"])
    assert analyzer._parse_timestamp(events[0]["timestamp"]) == dt.replace(tzinfo=None)


def test_input_is_not_mutated():
    events = [
        make_event(timestamp=datetime(2026, 9, 1, 10, 0, 0), user="Alice", process="notepad.exe", event_uid="evt-1"),
        make_event(timestamp=datetime(2026, 9, 10, 10, 0, 0), user="Alice", process="calc.exe", event_uid="evt-2"),
    ]
    original = copy.deepcopy(events)

    BehavioralAnalyzer(events).analyze()

    assert events == original


def test_deterministic_ordering_same_events_different_input_order():
    base_time = datetime(2026, 9, 15, 12, 0, 0, tzinfo=timezone.utc)
    events_a = [
        make_event(timestamp=base_time + timedelta(minutes=50), user="Alice", process="calc.exe", event_uid="evt-4"),
        make_event(timestamp=base_time + timedelta(minutes=10), user="Alice", process="notepad.exe", event_uid="evt-1"),
        make_event(timestamp=base_time + timedelta(minutes=20), user="Alice", process="outlook.exe", event_uid="evt-2"),
    ]
    events_b = list(reversed(events_a))

    findings_a = BehavioralAnalyzer(events_a).analyze()
    findings_b = BehavioralAnalyzer(events_b).analyze()

    assert findings_a == findings_b


def test_temporal_split_is_dynamic_and_excludes_observation_from_baseline():
    historical = make_event(timestamp=datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc), user="Alice", process="notepad.exe", event_uid="hist-1")
    observation = make_event(timestamp=datetime(2026, 9, 14, 9, 0, 0, tzinfo=timezone.utc), user="Alice", process="teams.exe", event_uid="obs-1")
    analyzer = BehavioralAnalyzer([historical, observation])
    actual_max = max(
        timestamp
        for timestamp in [analyzer._parse_timestamp(event["timestamp"]) for event in analyzer.events]
        if timestamp is not None
    )

    assert analyzer._observation_cutoff == actual_max - timedelta(days=BehavioralAnalyzer.OBSERVATION_DAYS)
    assert all(self_ts < analyzer._observation_cutoff for self_ts in [analyzer._parse_timestamp(event["timestamp"]) for event in analyzer._baseline_events])
    assert all(self_ts >= analyzer._observation_cutoff for self_ts in [analyzer._parse_timestamp(event["timestamp"]) for event in analyzer._observation_events])
    assert observation["event_uid"] not in {event["event_uid"] for event in analyzer._baseline_by_user.get("Alice", [])}
    assert historical["event_uid"] not in {event["event_uid"] for event in analyzer._observation_by_user.get("Alice", [])}


def test_user_baselines_only_include_historical_behavior_and_exclude_system_users():
    max_timestamp = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
    historical_base = max_timestamp - timedelta(days=20)
    events = [
        make_event(timestamp=historical_base + timedelta(days=i), user="Alice", process="notepad.exe", command_line="notepad.exe", event_uid=f"a{i}")
        for i in range(3)
    ]
    events += [
        make_event(timestamp=historical_base + timedelta(days=0, hours=1), user="Alice", process="chrome.exe", command_line="chrome.exe", event_uid="a-chrome"),
        make_event(timestamp=max_timestamp - timedelta(days=3), user="Alice", process="calc.exe", command_line="calc.exe", event_uid="a-obs-1"),
        make_event(timestamp=max_timestamp - timedelta(days=1), user="SYSTEM", process="services.exe", command_line="services.exe", event_uid="sys-1"),
        make_event(timestamp=max_timestamp - timedelta(days=2), user="NT AUTHORITY\\SYSTEM", process="lsass.exe", command_line="lsass.exe", event_uid="sys-2"),
        make_event(timestamp=max_timestamp - timedelta(days=4), user="LOCAL SERVICE", process="svchost.exe", command_line="svchost.exe", event_uid="sys-3"),
        make_event(timestamp=max_timestamp - timedelta(days=5), user="NETWORK SERVICE", process="svchost.exe", command_line="svchost.exe", event_uid="sys-4"),
    ]

    analyzer = BehavioralAnalyzer(events)
    baselines = analyzer.build_user_baselines()
    keys = {key.lower(): value for key, value in baselines.items()}

    assert "alice" in keys
    assert "notepad.exe" in keys["alice"]["known_processes"]
    assert keys["alice"]["process_counts"]["notepad.exe"] >= 1
    assert keys["alice"]["command_counts"]["notepad.exe"] >= 1
    assert "system" not in keys
    assert "nt authority\\system" not in keys
    assert "local service" not in keys
    assert "network service" not in keys


def test_host_baselines_are_historical_only():
    base = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)
    historical = make_event(timestamp=base, user="Alice", host="WIN-CLIENT-01", process="notepad.exe", event_uid="hist-h1")
    observation = make_event(timestamp=base + timedelta(days=20), user="Alice", host="WIN-CLIENT-02", process="calc.exe", event_uid="obs-h1")
    analyzer = BehavioralAnalyzer([historical, observation])

    assert "WIN-CLIENT-02" not in analyzer.host_baselines
    assert "WIN-CLIENT-01" in analyzer.host_baselines
    assert analyzer.detect_host_deviation()[0]["finding_type"] == "host_deviation"


def test_after_hours_activity_detects_unusual_hour_and_has_required_evidence():
    max_timestamp = datetime(2026, 9, 16, 12, 0, 0, tzinfo=timezone.utc)
    historical_base = max_timestamp - timedelta(days=20)
    historical_events = [
        make_event(timestamp=historical_base + timedelta(days=day, hours=9), user="Alice", process="notepad.exe", event_uid=f"hist-ah-{day}")
        for day in range(6)
    ]
    historical_events += [
        make_event(timestamp=historical_base + timedelta(days=day, hours=17), user="Alice", process="chrome.exe", event_uid=f"hist-ah-late-{day}")
        for day in range(6)
    ]
    observation_event = make_event(timestamp=max_timestamp - timedelta(days=2, hours=3), user="Alice", process="outlook.exe", event_uid="obs-ah-1")
    analyzer = BehavioralAnalyzer(historical_events + [observation_event])

    findings = analyzer.detect_after_hours_activity()
    matching = [item for item in findings if item["user"] == "Alice" and item["finding_type"] == "after_hours_activity"]
    assert matching
    evidence = matching[0]["evidence"]
    assert "observed_hour" in evidence
    assert "normal_hours" in evidence
    assert "historical_hour_counts" in evidence
    assert "historical_active_day_counts" in evidence

    normal_user_events = [
        make_event(timestamp=historical_base + timedelta(days=day, hours=10), user="Frank", process="notepad.exe", event_uid=f"frank-{day}")
        for day in range(6)
    ]
    normal_finding = BehavioralAnalyzer(normal_user_events).detect_after_hours_activity()
    assert not normal_finding


def test_first_seen_process_detects_new_process_and_deduplicates():
    base = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)
    historical = [
        make_event(timestamp=base + timedelta(days=day), user="Alice", process="notepad.exe", event_uid=f"fs-h-{day}")
        for day in range(3)
    ]
    observation = [
        make_event(timestamp=base + timedelta(days=10, hours=1), user="Alice", process="calc.exe", event_uid="fs-o-1"),
        make_event(timestamp=base + timedelta(days=10, hours=2), user="Alice", process="calc.exe", event_uid="fs-o-2"),
    ]
    analyzer = BehavioralAnalyzer(historical + observation)

    findings = analyzer.detect_first_seen_process()
    matching = [item for item in findings if item["user"] == "Alice" and item["finding_type"] == "first_seen_process"]
    assert matching
    assert len(matching) == 1
    assert matching[0]["evidence"]["process"].lower() == "calc.exe"
    assert matching[0]["evidence"]["historical_process_absence"] is True


def test_process_frequency_anomaly_detects_cluster_and_rejects_small_increase():
    base = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)
    historical = [
        make_event(timestamp=base + timedelta(minutes=10 * i), user="Alice", process="powershell.exe", event_uid=f"pfa-h-{i}")
        for i in range(3)
    ]
    observation = [
        make_event(timestamp=base + timedelta(days=10, hours=1, minutes=5 * i), user="Alice", process="powershell.exe", event_uid=f"pfa-o-{i}")
        for i in range(6)
    ]
    analyzer = BehavioralAnalyzer(historical + observation)
    findings = analyzer.detect_process_frequency_anomaly()
    matching = [item for item in findings if item["user"] == "Alice" and item["finding_type"] == "process_frequency_anomaly"]
    assert matching
    evidence = matching[0]["evidence"]
    assert evidence["window_minutes"] == 60
    assert evidence["cluster_size"] >= 6
    assert "historical_comparable_count" in evidence
    assert "comparison_threshold" in evidence

    low_change_events = historical + [
        make_event(timestamp=base + timedelta(days=10, hours=1, minutes=5), user="Alice", process="powershell.exe", event_uid="pfa-low-1"),
        make_event(timestamp=base + timedelta(days=10, hours=1, minutes=15), user="Alice", process="powershell.exe", event_uid="pfa-low-2"),
        make_event(timestamp=base + timedelta(days=10, hours=1, minutes=25), user="Alice", process="powershell.exe", event_uid="pfa-low-3"),
    ]
    assert not BehavioralAnalyzer(low_change_events).detect_process_frequency_anomaly()


def test_new_process_relationship_detects_missing_relationship_and_deduplicates():
    base = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)
    historical = [
        make_event(timestamp=base + timedelta(days=day), user="Alice", process="notepad.exe", parent_process="explorer.exe", command_line="notepad.exe", event_uid=f"rel-h-{day}")
        for day in range(3)
    ]
    observation = [
        make_event(timestamp=base + timedelta(days=10, hours=1), user="Alice", process="notepad.exe", parent_process="outlook.exe", command_line="outlook.exe; notepad.exe", event_uid="rel-o-1"),
        make_event(timestamp=base + timedelta(days=10, hours=2), user="Alice", process="notepad.exe", parent_process="outlook.exe", command_line="outlook.exe; notepad.exe", event_uid="rel-o-2"),
    ]
    analyzer = BehavioralAnalyzer(historical + observation)

    findings = analyzer.detect_new_process_relationship()
    matching = [item for item in findings if item["user"] == "Alice" and item["finding_type"] == "new_process_relationship"]
    assert matching
    assert len(matching) == 1
    assert matching[0]["evidence"]["parent_process"].lower() == "outlook.exe"
    assert matching[0]["evidence"]["child_process"].lower() == "notepad.exe"
    assert "historical_relationship_evidence" in matching[0]["evidence"]


def test_host_deviation_detects_unseen_host_and_deduplicates():
    base = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)
    historical = [
        make_event(timestamp=base + timedelta(days=day), user="David", host="WIN-CLIENT-01", process="notepad.exe", event_uid=f"hd-h-{day}")
        for day in range(3)
    ]
    observation = [
        make_event(timestamp=base + timedelta(days=10, hours=1), user="David", host="WIN-CLIENT-02", process="calc.exe", event_uid="hd-o-1"),
        make_event(timestamp=base + timedelta(days=10, hours=2), user="David", host="WIN-CLIENT-02", process="calc.exe", event_uid="hd-o-2"),
    ]
    analyzer = BehavioralAnalyzer(historical + observation)

    findings = analyzer.detect_host_deviation()
    matching = [item for item in findings if item["user"] == "David" and item["finding_type"] == "host_deviation"]
    assert matching
    assert len(matching) == 1
    assert matching[0]["evidence"]["observed_host"].lower() == "win-client-02"
    assert "historical_known_hosts" in matching[0]["evidence"]


def test_burst_activity_detects_command_cluster_and_deduplicates():
    base = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)
    historical = [
        make_event(timestamp=base + timedelta(minutes=20 * i), user="Bob", process="python.exe", command_line="python.exe -m http.server 8080", event_uid=f"burst-h-{i}")
        for i in range(3)
    ]
    observation = [
        make_event(timestamp=base + timedelta(days=10, hours=1, minutes=5 * i), user="Bob", process="python.exe", command_line="python.exe -m http.server 8080", event_uid=f"burst-o-{i}")
        for i in range(4)
    ]
    analyzer = BehavioralAnalyzer(historical + observation)

    findings = analyzer.detect_burst_activity()
    matching = [item for item in findings if item["user"] == "Bob" and item["finding_type"] == "burst_activity"]
    assert matching
    assert len(matching) == 1
    evidence = matching[0]["evidence"]
    assert evidence["normalized_command"].lower() == "python.exe -m http.server 8080"
    assert evidence["cluster_size"] >= 4
    assert evidence["window_minutes"] == 30
    assert "cluster_timestamps" in evidence
    assert "historical_comparable_count" in evidence
    assert "comparison_threshold" in evidence

    normal_command_events = historical + [
        make_event(timestamp=base + timedelta(days=10, hours=1, minutes=20), user="Bob", process="python.exe", command_line="python.exe -m http.server 8081", event_uid="burst-low-1"),
        make_event(timestamp=base + timedelta(days=10, hours=1, minutes=40), user="Bob", process="python.exe", command_line="python.exe -m http.server 8081", event_uid="burst-low-2"),
    ]
    assert not BehavioralAnalyzer(normal_command_events).detect_burst_activity()


def test_findings_have_required_schema_and_are_json_serializable():
    base = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(timestamp=base, user="Alice", process="notepad.exe", event_uid="schema-1"),
        make_event(timestamp=base + timedelta(days=10), user="Alice", process="calc.exe", event_uid="schema-2"),
    ]
    findings = BehavioralAnalyzer(events).analyze()

    assert findings
    for finding in findings:
        assert {"finding_type", "severity", "user", "host", "timestamp", "description", "evidence"}.issubset(finding)
        assert finding["severity"] in {"low", "medium", "high"}
        assert isinstance(finding["evidence"], dict)
        json.dumps(finding)


def test_real_behavioral_history_six_intentional_scenarios(real_behavioral_dataset):
    analyzer = BehavioralAnalyzer(real_behavioral_dataset)
    findings = analyzer.analyze()

    after_hours = [
        finding
        for finding in findings
        if finding["finding_type"] == "after_hours_activity" and str(finding.get("user", "")).lower() == "alice"
    ]
    assert any(
        "2026-09-10T02:09:00Z" in str(finding.get("timestamp", ""))
        or (finding.get("evidence", {}).get("observed_hour") == 2 and str(finding.get("user", "")).lower() == "alice")
        for finding in after_hours
    )

    first_seen = [
        finding
        for finding in findings
        if finding["finding_type"] == "first_seen_process"
        and str(finding.get("user", "")).lower() == "alice"
        and str(finding.get("evidence", {}).get("process", "")).lower() == "teams.exe"
    ]
    assert first_seen, "Alice first-seen teams.exe scenario missing from the real dataset"

    process_frequency = [
        finding
        for finding in findings
        if finding["finding_type"] == "process_frequency_anomaly"
        and str(finding.get("user", "")).lower() == "carol"
        and str(finding.get("evidence", {}).get("process", "")).lower() == "powershell.exe"
    ]
    assert process_frequency, "Carol process-frequency anomaly scenario missing from the real dataset"
    cluster_timestamps = process_frequency[0]["evidence"].get("cluster_timestamps", [])
    assert len(cluster_timestamps) >= 6, "Carol process-frequency cluster should contain at least six timestamps"

    relationship = [
        finding
        for finding in findings
        if finding["finding_type"] == "new_process_relationship"
        and str(finding.get("user", "")).lower() == "alice"
        and str(finding.get("evidence", {}).get("parent_process", "")).lower() == "outlook.exe"
        and str(finding.get("evidence", {}).get("child_process", "")).lower() == "notepad.exe"
    ]
    assert relationship, "Alice outlook.exe -> notepad.exe relationship scenario missing from the real dataset"

    host_deviation = [
        finding
        for finding in findings
        if finding["finding_type"] == "host_deviation"
        and str(finding.get("user", "")).lower() == "david"
        and str(finding.get("host", "")).lower() == "win-client-02"
    ]
    assert host_deviation, "David WIN-CLIENT-02 host deviation scenario missing from the real dataset"

    burst = [
        finding
        for finding in findings
        if finding["finding_type"] == "burst_activity"
        and str(finding.get("user", "")).lower() == "bob"
        and str(finding.get("evidence", {}).get("normalized_command", "")).lower() == "python.exe -m http.server 8080"
    ]
    assert burst, "Bob python.exe -m http.server 8080 burst scenario missing from the real dataset"


def test_duplicate_suppression_for_first_seen_user_process():
    base = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(timestamp=base + timedelta(days=day), user="Alice", process="calc.exe", event_uid=f"dup-fs-{day}")
        for day in range(3)
    ]
    events += [
        make_event(timestamp=base + timedelta(days=10, hours=1), user="Alice", process="teams.exe", event_uid="dup-fs-o-1"),
        make_event(timestamp=base + timedelta(days=10, hours=2), user="Alice", process="teams.exe", event_uid="dup-fs-o-2"),
    ]
    findings = BehavioralAnalyzer(events).detect_first_seen_process()
    assert len([item for item in findings if item["user"] == "Alice" and item["evidence"]["process"] == "teams.exe"]) == 1


def test_duplicate_suppression_for_relationship_and_host_and_burst_and_frequency():
    base = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)

    rel_history = [
        make_event(timestamp=base + timedelta(days=day), user="Alice", process="notepad.exe", parent_process="explorer.exe", event_uid=f"dup-rel-h-{day}")
        for day in range(3)
    ]
    rel_obs = [
        make_event(timestamp=base + timedelta(days=10, hours=1), user="Alice", process="notepad.exe", parent_process="outlook.exe", event_uid="dup-rel-o-1"),
        make_event(timestamp=base + timedelta(days=10, hours=2), user="Alice", process="notepad.exe", parent_process="outlook.exe", event_uid="dup-rel-o-2"),
    ]
    relationship_findings = BehavioralAnalyzer(rel_history + rel_obs).detect_new_process_relationship()
    assert len([item for item in relationship_findings if item["user"] == "Alice"]) == 1

    host_history = [
        make_event(timestamp=base + timedelta(days=day), user="David", host="WIN-CLIENT-01", process="notepad.exe", event_uid=f"dup-host-h-{day}")
        for day in range(3)
    ]
    host_obs = [
        make_event(timestamp=base + timedelta(days=10, hours=1), user="David", host="WIN-CLIENT-02", process="calc.exe", event_uid="dup-host-o-1"),
        make_event(timestamp=base + timedelta(days=10, hours=2), user="David", host="WIN-CLIENT-02", process="calc.exe", event_uid="dup-host-o-2"),
    ]
    host_findings = BehavioralAnalyzer(host_history + host_obs).detect_host_deviation()
    assert len([item for item in host_findings if item["user"] == "David"]) == 1

    freq_history = [
        make_event(timestamp=base + timedelta(minutes=10 * i), user="Alice", process="powershell.exe", event_uid=f"dup-freq-h-{i}")
        for i in range(3)
    ]
    freq_obs = [
        make_event(timestamp=base + timedelta(days=10, hours=1, minutes=5 * i), user="Alice", process="powershell.exe", event_uid=f"dup-freq-o-{i}")
        for i in range(6)
    ]
    freq_findings = BehavioralAnalyzer(freq_history + freq_obs).detect_process_frequency_anomaly()
    assert len(freq_findings) <= 1

    cmd_history = [
        make_event(timestamp=base + timedelta(minutes=20 * i), user="Bob", process="python.exe", command_line="python.exe -m http.server 8080", event_uid=f"dup-burst-h-{i}")
        for i in range(3)
    ]
    cmd_obs = [
        make_event(timestamp=base + timedelta(days=10, hours=1, minutes=5 * i), user="Bob", process="python.exe", command_line="python.exe -m http.server 8080", event_uid=f"dup-burst-o-{i}")
        for i in range(4)
    ]
    burst_findings = BehavioralAnalyzer(cmd_history + cmd_obs).detect_burst_activity()
    assert len(burst_findings) <= 1


def test_normal_behavior_does_not_generate_repetitive_findings():
    base = datetime(2026, 9, 1, 9, 0, 0, tzinfo=timezone.utc)
    events = [
        make_event(timestamp=base + timedelta(days=day, hours=10), user="Alice", process="notepad.exe", event_uid=f"normal-{day}")
        for day in range(12)
    ]
    observation = [
        make_event(timestamp=base + timedelta(days=20, hours=10), user="Alice", process="notepad.exe", event_uid="normal-obs-1"),
        make_event(timestamp=base + timedelta(days=20, hours=10, minutes=5), user="Alice", process="notepad.exe", event_uid="normal-obs-2"),
        make_event(timestamp=base + timedelta(days=20, hours=10, minutes=10), user="Alice", process="notepad.exe", event_uid="normal-obs-3"),
    ]
    findings = BehavioralAnalyzer(events + observation).analyze()
    assert not any(f["finding_type"] in {"first_seen_process", "process_frequency_anomaly", "burst_activity"} for f in findings)
