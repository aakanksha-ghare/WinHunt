import copy
import json

from app.risk_scorer import RiskScorer


def make_finding(
    finding_type="unknown",
    severity="medium",
    evidence=None,
):
    return {
        "finding_type": finding_type,
        "severity": severity,
        "user": "alice",
        "host": "WIN-CLIENT-01",
        "timestamp": "2026-09-15T12:00:00Z",
        "description": "Test finding",
        "evidence": evidence if evidence is not None else {},
    }


def test_base_severity_scores():
    scorer = RiskScorer()

    assert scorer.score_finding(make_finding(severity="low"))["risk_score"] == 20
    assert scorer.score_finding(make_finding(severity="medium"))["risk_score"] == 40
    assert scorer.score_finding(make_finding(severity="high"))["risk_score"] == 60


def test_risk_level_boundaries():
    scorer = RiskScorer()

    assert scorer._risk_level_for_score(0) == "low"
    assert scorer._risk_level_for_score(29) == "low"
    assert scorer._risk_level_for_score(30) == "medium"
    assert scorer._risk_level_for_score(59) == "medium"
    assert scorer._risk_level_for_score(60) == "high"
    assert scorer._risk_level_for_score(79) == "high"
    assert scorer._risk_level_for_score(80) == "critical"
    assert scorer._risk_level_for_score(100) == "critical"


def test_invalid_severity_defaults_to_medium():
    scorer = RiskScorer()

    for severity in ("invalid", "", None, 123):
        result = scorer.score_finding(make_finding(severity=severity))
        assert result["risk_score"] == 40
        assert result["risk_level"] == "medium"


def test_after_hours_factor_is_not_duplicated():
    scorer = RiskScorer()

    finding = make_finding(
        finding_type="after_hours_activity",
        severity="medium",
        evidence={
            "observed_hour": 2,
            "normal_hours": [9, 10, 11],
        },
    )

    result = scorer.score_finding(finding)
    factors = [factor["factor"] for factor in result["risk_factors"]]

    assert factors.count("after_hours") == 1
    assert result["risk_score"] > 40


def test_first_seen_process_adds_context():
    scorer = RiskScorer()

    result = scorer.score_finding(
        make_finding(
            finding_type="first_seen_process",
            severity="medium",
            evidence={
                "process": "teams.exe",
                "historical_process_absence": True,
            },
        )
    )

    assert result["risk_score"] > 40
    assert any(
        factor["factor"] == "first_seen_process"
        for factor in result["risk_factors"]
    )


def test_frequency_anomaly_adds_context():
    scorer = RiskScorer()

    result = scorer.score_finding(
        make_finding(
            finding_type="process_frequency_anomaly",
            severity="high",
            evidence={
                "process": "powershell.exe",
                "cluster_size": 6,
                "window_minutes": 60,
                "historical_comparable_count": 1,
                "comparison_threshold": 2,
            },
        )
    )

    assert result["risk_score"] > 60
    assert any(
        factor["factor"] == "process_frequency_anomaly"
        for factor in result["risk_factors"]
    )


def test_encoded_powershell_is_not_double_counted():
    scorer = RiskScorer()

    result = scorer.score_finding(
        make_finding(
            finding_type="encoded_powershell",
            severity="high",
            evidence={
                "command_line": "powershell.exe -enc QQ==",
            },
        )
    )

    factors = [factor["factor"] for factor in result["risk_factors"]]

    assert factors.count("encoded_powershell") == 1
    assert result["risk_score"] > 60


def test_office_to_powershell_adds_signal():
    scorer = RiskScorer()

    result = scorer.score_finding(
        make_finding(
            finding_type="office_to_powershell",
            severity="high",
            evidence={
                "parent_process": "winword.exe",
                "process": "powershell.exe",
            },
        )
    )

    assert result["risk_score"] > 60
    assert any(
        factor["factor"] == "office_to_powershell"
        for factor in result["risk_factors"]
    )


def test_suspicious_location_adds_signal():
    scorer = RiskScorer()

    result = scorer.score_finding(
        make_finding(
            finding_type="suspicious_executable_location",
            severity="medium",
            evidence={
                "path": r"C:\Users\alice\AppData\Local\Temp\payload.exe",
            },
        )
    )

    assert result["risk_score"] > 40


def test_scheduled_task_adds_signal():
    scorer = RiskScorer()

    result = scorer.score_finding(
        make_finding(
            finding_type="scheduled_task_creation",
            severity="medium",
            evidence={
                "task_name": "UpdaterTask",
            },
        )
    )

    assert result["risk_score"] > 40
    assert any(
        factor["factor"] == "scheduled_task_creation"
        for factor in result["risk_factors"]
    )


def test_score_is_bounded():
    scorer = RiskScorer()

    result = scorer.score_finding(
        make_finding(
            finding_type="encoded_powershell",
            severity="high",
            evidence={
                "command_line": "powershell.exe -enc QQ==",
                "observed_hour": 2,
                "normal_hours": [9],
                "historical_process_absence": True,
                "cluster_size": 10,
                "window_minutes": 30,
                "path": r"C:\Users\alice\AppData\Local\Temp\a.exe",
                "task_name": "PersistenceTask",
            },
        )
    )

    assert 0 <= result["risk_score"] <= 100


def test_unknown_finding_type_does_not_crash():
    scorer = RiskScorer()

    result = scorer.score_finding(
        make_finding(
            finding_type="future_detection",
            severity="medium",
        )
    )

    assert result["risk_score"] == 40
    assert result["risk_level"] == "medium"


def test_missing_or_invalid_evidence_does_not_crash():
    scorer = RiskScorer()

    for evidence in (None, "invalid", [], 123):
        result = scorer.score_finding(
            make_finding(
                finding_type="host_deviation",
                evidence=evidence,
            )
        )

        assert 0 <= result["risk_score"] <= 100
        assert isinstance(result["risk_factors"], list)


def test_input_is_not_mutated():
    scorer = RiskScorer()

    finding = make_finding(
        finding_type="first_seen_process",
        evidence={
            "process": "teams.exe",
            "historical_process_absence": True,
            "nested": {"value": 1},
        },
    )

    original = copy.deepcopy(finding)
    result = scorer.score_finding(finding)

    assert finding == original
    assert result is not finding
    assert result["evidence"] is not finding["evidence"]


def test_score_findings_preserves_order():
    scorer = RiskScorer()

    findings = [
        make_finding("first_seen_process"),
        make_finding("encoded_powershell", "high"),
        make_finding("host_deviation", "low"),
    ]

    original = copy.deepcopy(findings)
    results = scorer.score_findings(findings)

    assert [r["finding_type"] for r in results] == [
        r["finding_type"] for r in findings
    ]
    assert findings == original


def test_scoring_is_deterministic_and_json_serializable():
    scorer = RiskScorer()

    finding = make_finding(
        finding_type="process_frequency_anomaly",
        severity="high",
        evidence={
            "process": "powershell.exe",
            "cluster_size": 6,
            "window_minutes": 60,
            "historical_comparable_count": 1,
        },
    )

    result1 = scorer.score_finding(finding)
    result2 = scorer.score_finding(finding)

    assert result1 == result2
    json.dumps(result1)