"""WinHunt analysis service orchestration.

This module coordinates the validated WinHunt backend analysis pipeline.
It reuses the existing parser, detection, behavioral analysis,
authentication/persistence hunting, risk scoring, correlation, and
MITRE ATT&CK mapping components.

The service layer is responsible only for orchestration and returning
structured results for the Flask application.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.auth_persistence_hunter import AuthPersistenceHunter
from app.behavioral_analyzer import BehavioralAnalyzer
from app.correlation_engine import EventCorrelator
from app.detection_engine import detect_events
from app.mitre_mapper import map_chain, map_findings
from app.parser import parse_events
from app.risk_scorer import RiskScorer


class WinHuntService:
    """Coordinate the complete WinHunt analysis pipeline."""

    def __init__(self) -> None:
        """Initialize the analysis service and its risk scorer."""
        self.risk_scorer = RiskScorer()

    @staticmethod
    def _prepare_events(events: Any) -> list[dict[str, Any]]:
        """Validate and normalize the input container.

        WinHunt accepts either:
        - a single event dictionary, or
        - an iterable of event dictionaries.

        Invalid event items are rejected rather than silently discarded,
        because silently dropping telemetry could hide ingestion problems.
        """
        if events is None:
            return []

        if isinstance(events, dict):
            return [events]

        if isinstance(events, (str, bytes)):
            raise TypeError(
                "events must be a dictionary or an iterable of dictionaries"
            )

        if not isinstance(events, Iterable):
            raise TypeError(
                "events must be a dictionary or an iterable of dictionaries"
            )

        raw_events = list(events)

        invalid_items = [
            index
            for index, event in enumerate(raw_events)
            if not isinstance(event, dict)
        ]

        if invalid_items:
            raise TypeError(
                "events must contain only dictionaries; "
                f"invalid item indexes: {invalid_items}"
            )

        return raw_events

    @staticmethod
    def _build_summary(
        raw_events: list[dict[str, Any]],
        findings: list[dict[str, Any]],
        chains: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build the dashboard summary from final analysis results."""
        severity_counts = {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }

        for finding in findings:
            level = str(
                finding.get("risk_level") or ""
            ).strip().lower()

            if level in severity_counts:
                severity_counts[level] += 1

        return {
            "event_count": len(raw_events),
            "finding_count": len(findings),
            "chain_count": len(chains),
            "severity_counts": severity_counts,
        }

    def analyze_events(self, events: Any) -> dict[str, Any]:
        """Run the complete WinHunt analysis pipeline.

        Pipeline:
            Raw events
                ↓
            Parser / normalization
                ↓
            Rule-based detection
                ↓
            Behavioral analysis
                ↓
            Authentication / persistence hunting
                ↓
            Risk scoring
                ↓
            MITRE ATT&CK mapping
                ↓
            Event correlation
                ↓
            Chain-level MITRE mapping
                ↓
            Structured result
        """
        raw_events = self._prepare_events(events)

        # 1. Normalize raw telemetry into WinHunt's common event schema.
        normalized_events = parse_events(raw_events)

        # 2. Run deterministic rule-based detections.
        detection_findings = detect_events(normalized_events)

        # 3. Analyze behavioral deviations from historical baselines.
        behavioral_findings = BehavioralAnalyzer(
            normalized_events
        ).analyze()

        # 4. Hunt authentication and persistence activity.
        auth_findings = AuthPersistenceHunter(
            normalized_events
        ).analyze()

        # 5. Combine all independent finding sources.
        findings = (
            detection_findings
            + behavioral_findings
            + auth_findings
        )

        # 6. Calculate explainable risk scores.
        scored_findings = self.risk_scorer.score_findings(findings)

        # 7. Enrich individual findings with conservative MITRE mappings.
        mapped_findings = map_findings(scored_findings)

        # 8. Correlate related findings into investigation chains.
        chains = EventCorrelator(
            findings=mapped_findings,
            events=normalized_events,
        ).correlate()

        # 9. Add chain-level MITRE ATT&CK enrichment.
        mapped_chains = [
            map_chain(chain)
            for chain in chains
        ]

        # 10. Build dashboard/API summary.
        summary = self._build_summary(
            raw_events=raw_events,
            findings=mapped_findings,
            chains=mapped_chains,
        )

        return {
            "findings": mapped_findings,
            "chains": mapped_chains,
            "summary": summary,
        }


__all__ = ["WinHuntService"]