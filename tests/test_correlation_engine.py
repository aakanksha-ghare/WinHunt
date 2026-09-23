from __future__ import annotations

import copy
import json

import pytest

from app.correlation_engine import (
    DEFAULT_CORRELATION_WINDOW_MINUTES,
    DEFAULT_WEAK_HOST_WINDOW_MINUTES,
    EventCorrelator,
    build_attack_chains,
    correlate_findings,
)


def make_finding(
    finding_type="encoded_powershell",
    timestamp="2026-09-15T10:00:00Z",
    host="WIN-CLIENT-01",
    user="alice",
    **kwargs,
):
    finding = {
        "finding_type": finding_type,
        "timestamp": timestamp,
        "host": host,
        "user": user,
        "description": f"Test finding: {finding_type}",
        "evidence": {},
    }
    finding.update(kwargs)
    return finding


def test_none_input_returns_empty():
    assert correlate_findings(None) == []


def test_empty_input_returns_empty():
    assert correlate_findings([]) == []


def test_malformed_findings_are_ignored():
    findings = [
        None,
        "not a finding",
        123,
        [],
        {},
        make_finding(),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1
    assert chains[0]["finding_count"] == 1


def test_same_host_same_user_within_30_minutes_correlates():
    findings = [
        make_finding(timestamp="2026-09-15T10:00:00Z"),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:29:00Z",
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1
    assert chains[0]["finding_count"] == 2

    reasons = {
        reason
        for pair in chains[0]["correlation_reasons"]
        for reason in pair["reasons"]
    }

    assert "same_host" in reasons
    assert "same_user" in reasons
    assert "within_30_minutes" in reasons


def test_same_host_same_user_over_30_minutes_does_not_correlate():
    findings = [
        make_finding(timestamp="2026-09-15T10:00:00Z"),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:31:00Z",
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 2


def test_same_host_without_user_within_10_minutes_correlates():
    findings = [
        make_finding(
            timestamp="2026-09-15T10:00:00Z",
            user=None,
        ),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:09:00Z",
            user=None,
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1

    reasons = {
        reason
        for pair in chains[0]["correlation_reasons"]
        for reason in pair["reasons"]
    }

    assert "within_10_minutes" in reasons


def test_same_host_without_user_over_10_minutes_does_not_correlate():
    findings = [
        make_finding(
            timestamp="2026-09-15T10:00:00Z",
            user=None,
        ),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:11:00Z",
            user=None,
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 2


def test_different_hosts_do_not_correlate_by_time_and_user():
    findings = [
        make_finding(timestamp="2026-09-15T10:00:00Z", host="HOST-A"),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:05:00Z",
            host="HOST-B",
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 2


def test_shared_pid_creates_strong_correlation():
    findings = [
        make_finding(
            timestamp="2026-09-15T10:00:00Z",
            pid=2420,
        ),
        make_finding(
            finding_type="suspicious_executable_location",
            timestamp="2026-09-15T10:05:00Z",
            pid=2420,
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1

    reasons = {
        reason
        for pair in chains[0]["correlation_reasons"]
        for reason in pair["reasons"]
    }

    assert "shared_pid" in reasons


def test_parent_child_pid_relationship_correlates():
    findings = [
        make_finding(
            timestamp="2026-09-15T10:00:00Z",
            pid=2404,
            process="winword.exe",
        ),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:01:00Z",
            pid=2420,
            parent_pid=2404,
            process="powershell.exe",
            parent_process="winword.exe",
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1

    reasons = {
        reason
        for pair in chains[0]["correlation_reasons"]
        for reason in pair["reasons"]
    }

    assert "parent_child_process" in reasons


def test_shared_process_guid_correlates():
    findings = [
        make_finding(
            timestamp="2026-09-15T10:00:00Z",
            process_guid="{GUID-001}",
        ),
        make_finding(
            finding_type="suspicious_executable_location",
            timestamp="2026-09-15T10:03:00Z",
            process_guid="{GUID-001}",
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1

    reasons = {
        reason
        for pair in chains[0]["correlation_reasons"]
        for reason in pair["reasons"]
    }

    assert "shared_process_guid" in reasons


def test_top_level_process_fields_are_used():
    findings = [
        make_finding(
            timestamp="2026-09-15T10:00:00Z",
            pid=2420,
            process="powershell.exe",
            parent_pid=2404,
            parent_process="winword.exe",
        ),
        make_finding(
            finding_type="suspicious_executable_location",
            timestamp="2026-09-15T10:02:00Z",
            pid=2420,
            process="powershell.exe",
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1

    reasons = {
        reason
        for pair in chains[0]["correlation_reasons"]
        for reason in pair["reasons"]
    }

    assert "shared_pid" in reasons
    assert "shared_process" in reasons


def test_evidence_fields_are_used_as_fallback():
    findings = [
        make_finding(
            timestamp="2026-09-15T10:00:00Z",
            evidence={
                "pid": 2420,
                "process": "powershell.exe",
            },
        ),
        make_finding(
            finding_type="suspicious_executable_location",
            timestamp="2026-09-15T10:02:00Z",
            evidence={
                "pid": 2420,
                "process": "powershell.exe",
            },
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1

    reasons = {
        reason
        for pair in chains[0]["correlation_reasons"]
        for reason in pair["reasons"]
    }

    assert "shared_pid" in reasons


def test_top_level_value_takes_precedence_over_evidence():
    findings = [
        make_finding(
            timestamp="2026-09-15T10:00:00Z",
            pid=2420,
            evidence={"pid": 9999},
        ),
        make_finding(
            finding_type="suspicious_executable_location",
            timestamp="2026-09-15T10:02:00Z",
            pid=2420,
            evidence={"pid": 8888},
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1


def test_office_to_powershell_chain():
    findings = [
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:00:00Z",
            pid=2420,
            parent_pid=2404,
            process="powershell.exe",
            parent_process="winword.exe",
        ),
        make_finding(
            finding_type="encoded_powershell",
            timestamp="2026-09-15T10:02:00Z",
            pid=2420,
            process="powershell.exe",
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1
    assert chains[0]["finding_count"] == 2
    assert chains[0]["stages"] == ["execution", "execution"]


def test_persistence_relationship():
    findings = [
        make_finding(
            finding_type="suspicious_executable_location",
            timestamp="2026-09-15T10:00:00Z",
            pid=2420,
        ),
        make_finding(
            finding_type="scheduled_task_persistence",
            timestamp="2026-09-15T10:05:00Z",
            evidence={"task_name": "UpdaterTask"},
        ),
        make_finding(
            finding_type="scheduled_task_persistence",
            timestamp="2026-09-15T10:06:00Z",
            evidence={"task_name": "UpdaterTask"},
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1
    assert chains[0]["finding_count"] == 3
    assert "persistence" in chains[0]["stages"]


def test_behavioral_finding_can_correlate_with_execution():
    findings = [
        make_finding(
            finding_type="encoded_powershell",
            timestamp="2026-09-15T10:00:00Z",
        ),
        make_finding(
            finding_type="after_hours_activity",
            timestamp="2026-09-15T10:10:00Z",
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1


def test_duplicate_findings_are_deduplicated():
    finding = make_finding(
        timestamp="2026-09-15T10:00:00Z",
        event_uid="EVENT-001",
    )

    chains = correlate_findings([finding, copy.deepcopy(finding)])

    assert len(chains) == 1
    assert chains[0]["finding_count"] == 1


def test_missing_timestamps_do_not_crash():
    findings = [
        make_finding(timestamp=None),
        make_finding(
            finding_type="office_to_powershell",
            timestamp=None,
        ),
    ]

    chains = correlate_findings(findings)

    assert isinstance(chains, list)


def test_chain_is_chronologically_ordered():
    findings = [
        make_finding(
            finding_type="encoded_powershell",
            timestamp="2026-09-15T10:10:00Z",
        ),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:00:00Z",
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1

    timestamps = [
        finding["timestamp"]
        for finding in chains[0]["findings"]
    ]

    assert timestamps == [
        "2026-09-15T10:00:00Z",
        "2026-09-15T10:10:00Z",
    ]


def test_chain_schema():
    findings = [
        make_finding(),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:05:00Z",
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1

    chain = chains[0]

    required_keys = {
        "chain_id",
        "start_time",
        "end_time",
        "duration_seconds",
        "host",
        "users",
        "finding_count",
        "stages",
        "findings",
        "correlation_reasons",
    }

    assert required_keys.issubset(chain.keys())
    assert chain["chain_id"].startswith("CHAIN-")
    assert chain["finding_count"] == len(chain["findings"])


def test_risk_fields_are_not_modified():
    findings = [
        make_finding(
            risk_score=72,
            risk_level="high",
            risk_factors=["encoded_powershell"],
        ),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:05:00Z",
            risk_score=84,
            risk_level="critical",
            risk_factors=["office_to_powershell"],
        ),
    ]

    chains = correlate_findings(findings)

    assert len(chains) == 1

    first = chains[0]["findings"][0]
    second = chains[0]["findings"][1]

    assert first["risk_score"] == 72
    assert first["risk_level"] == "high"
    assert first["risk_factors"] == ["encoded_powershell"]

    assert second["risk_score"] == 84
    assert second["risk_level"] == "critical"
    assert second["risk_factors"] == ["office_to_powershell"]


def test_input_is_not_mutated():
    findings = [
        make_finding(
            pid=2420,
            evidence={"command_line": "powershell.exe -enc ABC"},
        ),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:05:00Z",
            pid=2420,
        ),
    ]

    original = copy.deepcopy(findings)

    correlate_findings(findings)

    assert findings == original


def test_output_is_json_serializable():
    findings = [
        make_finding(),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:05:00Z",
        ),
    ]

    chains = correlate_findings(findings)

    json.dumps(chains)


def test_output_is_deterministic():
    findings = [
        make_finding(
            finding_type="encoded_powershell",
            timestamp="2026-09-15T10:02:00Z",
        ),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:00:00Z",
        ),
        make_finding(
            finding_type="suspicious_executable_location",
            timestamp="2026-09-15T10:05:00Z",
        ),
    ]

    first = correlate_findings(findings)
    second = correlate_findings(list(reversed(findings)))

    assert first == second


def test_convenience_functions_match_class_api():
    findings = [
        make_finding(),
        make_finding(
            finding_type="office_to_powershell",
            timestamp="2026-09-15T10:05:00Z",
        ),
    ]

    assert correlate_findings(findings) == EventCorrelator(findings).correlate()
    assert build_attack_chains(findings) == EventCorrelator(findings).build_attack_chains()


def test_constants_match_required_windows():
    assert DEFAULT_CORRELATION_WINDOW_MINUTES == 30
    assert DEFAULT_WEAK_HOST_WINDOW_MINUTES == 10