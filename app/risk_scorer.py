"""Risk-scoring layer for WinHunt detections and behavioral findings."""

from __future__ import annotations

import copy
from typing import Any, Iterable


class RiskScorer:
    """Convert a detection or behavioral finding into a bounded, explainable risk score."""

    BASE_SEVERITY_SCORES = {
        "low": 20,
        "medium": 40,
        "high": 60,
    }

    RISK_LEVELS = (
        (0, 29, "low"),
        (30, 59, "medium"),
        (60, 79, "high"),
        (80, 100, "critical"),
    )

    BEHAVIORAL_BONUSES = {
        "after_hours_activity": 10,
        "first_seen_process": 15,
        "process_frequency_anomaly": 15,
        "new_process_relationship": 12,
        "host_deviation": 12,
        "burst_activity": 15,
    }

    RULE_SIGNAL_BONUSES = {
        "encoded_powershell": 12,
        "office_to_powershell": 12,
        "suspicious_executable_location": 8,
        "scheduled_task_creation": 10,
    }

    DEFAULT_SEVERITY = "medium"

    @classmethod
    def _normalize_severity(cls, severity: Any) -> str:
        if not isinstance(severity, str):
            return cls.DEFAULT_SEVERITY
        normalized = severity.strip().lower()
        return normalized if normalized in cls.BASE_SEVERITY_SCORES else cls.DEFAULT_SEVERITY

    @classmethod
    def _normalize_finding_type(cls, finding: dict[str, Any]) -> str:
        if not isinstance(finding, dict):
            return "unknown"

        for key in ("finding_type", "rule_name", "rule_id"):
            value = finding.get(key)
            if value is None:
                continue
            text = str(value).strip().lower()
            if text:
                return text
        return "unknown"

    @classmethod
    def _clamp_score(cls, value: int) -> int:
        return max(0, min(100, int(value)))

    @classmethod
    def _risk_level_for_score(cls, score: int) -> str:
        for lower, upper, label in cls.RISK_LEVELS:
            if lower <= score <= upper:
                return label
        return "low"

    @classmethod
    def _finding_type_hint(cls, finding_type: str) -> str:
        type_name = str(finding_type).strip().lower()
        if "encoded" in type_name and "powershell" in type_name:
            return "encoded_powershell"
        if "office" in type_name and "powershell" in type_name:
            return "office_to_powershell"
        if "suspicious" in type_name and "executable" in type_name:
            return "suspicious_executable_location"
        if "scheduled" in type_name and "task" in type_name:
            return "scheduled_task_creation"
        return type_name

    @classmethod
    def _evidence_value(cls, evidence: Any, *keys: str) -> Any:
        if not isinstance(evidence, dict):
            return None
        for key in keys:
            if key in evidence:
                return evidence.get(key)
        return None

    def _base_factor(self, severity: str, score: int) -> dict[str, Any]:
        return {
            "factor": "base_severity",
            "points": score,
            "reason": f"{severity.title()}-severity detection",
        }

    def _behavioral_factors(self, finding: dict[str, Any]) -> list[dict[str, Any]]:
        factors: list[dict[str, Any]] = []
        finding_type = self._normalize_finding_type(finding)
        evidence = finding.get("evidence") if isinstance(finding, dict) else {}

        if isinstance(evidence, dict):
            if "observed_hour" in evidence or "normal_hours" in evidence:
                factors.append(
                    {
                        "factor": "after_hours",
                        "points": 10,
                        "reason": "Activity occurred outside historical user hours",
                    }
                )
            if "historical_process_absence" in evidence or "historical_relationship_evidence" in evidence:
                factors.append(
                    {
                        "factor": "historical_context",
                        "points": 8,
                        "reason": "Activity deviated from established historical behavior",
                    }
                )
            if "cluster_size" in evidence and "window_minutes" in evidence:
                factors.append(
                    {
                        "factor": "burst_or_frequency",
                        "points": 10,
                        "reason": "Repeated execution formed a tight cluster relative to prior cadence",
                    }
                )

        normalized_type = self._finding_type_hint(finding_type)
        if normalized_type in self.BEHAVIORAL_BONUSES:
            factors.append(
                {
                    "factor": normalized_type,
                    "points": self.BEHAVIORAL_BONUSES[normalized_type],
                    "reason": self._behavioral_reason(normalized_type),
                }
            )

        # Mitigate duplicate counting for the same concept when an indicator is already represented by the type.
        seen = set()
        deduplicated: list[dict[str, Any]] = []
        for factor in factors:
            key = (factor["factor"], factor["points"], factor["reason"])
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(factor)
        return deduplicated

    @staticmethod
    def _behavioral_reason(factor: str) -> str:
        mapping = {
            "after_hours_activity": "Activity occurred outside historical user hours",
            "first_seen_process": "Process had not been observed in the historical baseline",
            "process_frequency_anomaly": "Process frequency exceeded historical cadence",
            "new_process_relationship": "Parent-child relationship was not seen in the historical baseline",
            "host_deviation": "User activity appeared on a previously unseen host",
            "burst_activity": "The same normalized command repeated unusually quickly",
        }
        return mapping.get(factor, "Behavioral deviation from historical patterns")

    def _rule_signal_factors(self, finding: dict[str, Any]) -> list[dict[str, Any]]:
        factors: list[dict[str, Any]] = []
        raw_type = self._normalize_finding_type(finding)
        normalized_type = self._finding_type_hint(raw_type)

        if normalized_type in self.RULE_SIGNAL_BONUSES:
            factors.append(
                {
                    "factor": normalized_type,
                    "points": self.RULE_SIGNAL_BONUSES[normalized_type],
                    "reason": self._rule_reason(normalized_type),
                }
            )

        evidence = finding.get("evidence") if isinstance(finding, dict) else {}
        if isinstance(evidence, dict):
            command_line = str(self._evidence_value(evidence, "command_line", "process_command") or "").lower()
            if "-enc" in command_line or "-encodedcommand" in command_line:
                factors.append(
                    {
                        "factor": "encoded_powershell",
                        "points": 12,
                        "reason": "Encoded PowerShell command indicates additional evasion risk",
                    }
                )

            parent = str(self._evidence_value(evidence, "parent_process") or "").lower()
            if parent.endswith("winword.exe") or parent.endswith("excel.exe") or parent.endswith("outlook.exe"):
                process_name = str(self._evidence_value(evidence, "process") or "").lower()
                if process_name.endswith("powershell.exe") or process_name.endswith("pwsh.exe"):
                    factors.append(
                        {
                            "factor": "office_to_powershell",
                            "points": 12,
                            "reason": "Office application spawned PowerShell",
                        }
                    )

            suspicious_path = str(self._evidence_value(evidence, "path") or "")
            if suspicious_path.lower().find("appdata") != -1 or suspicious_path.lower().find("temp") != -1:
                factors.append(
                    {
                        "factor": "suspicious_executable_location",
                        "points": 8,
                        "reason": "Executable path is in a user-writable or transient location",
                    }
                )

            task_name = self._evidence_value(evidence, "task_name")
            if task_name is not None or "task_name" in str(evidence):
                factors.append(
                    {
                        "factor": "scheduled_task_creation",
                        "points": 10,
                        "reason": "Scheduled task creation indicates persistence-oriented automation",
                    }
                )

        deduplicated: list[dict[str, Any]] = []
        seen = set()
        for factor in factors:
            key = (factor["factor"], factor["points"], factor["reason"])
            if key in seen:
                continue
            seen.add(key)
            deduplicated.append(factor)
        return deduplicated

    @staticmethod
    def _rule_reason(factor: str) -> str:
        mapping = {
            "encoded_powershell": "PowerShell command used an encoded payload indicator",
            "office_to_powershell": "Office application spawned PowerShell",
            "suspicious_executable_location": "Executable path was in a suspicious user-writable or temp location",
            "scheduled_task_creation": "Scheduled task creation is a persistence-oriented action",
        }
        return mapping.get(factor, "Security-relevant signal identified by rule logic")

    @classmethod
    def _score_from_factors(cls, factors: list[dict[str, Any]]) -> int:
        return sum(int(factor.get("points", 0)) for factor in factors)

    def score_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        """Return a copy of the finding with a deterministic risk score and explanation."""
        safe_finding = copy.deepcopy(finding) if isinstance(finding, dict) else {}
        if not isinstance(safe_finding, dict):
            safe_finding = {}

        severity = self._normalize_severity(safe_finding.get("severity"))
        base_score = self.BASE_SEVERITY_SCORES[severity]

        factors: list[dict[str, Any]] = [self._base_factor(severity, base_score)]
        factors.extend(self._behavioral_factors(safe_finding))
        factors.extend(self._rule_signal_factors(safe_finding))

        total_score = self._clamp_score(base_score + self._score_from_factors(factors[1:]))
        risk_level = self._risk_level_for_score(total_score)

        result = dict(safe_finding)
        result["risk_score"] = total_score
        result["risk_level"] = risk_level
        result["risk_factors"] = [
            {
                "factor": factor["factor"],
                "points": int(factor.get("points", 0)),
                "reason": factor.get("reason", ""),
            }
            for factor in factors
        ]
        return result

    def score_findings(self, findings: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
        """Score each finding while preserving input order and leaving original data unchanged."""
        if findings is None:
            return []

        result: list[dict[str, Any]] = []
        for finding in findings:
            result.append(self.score_finding(finding))
        return result
