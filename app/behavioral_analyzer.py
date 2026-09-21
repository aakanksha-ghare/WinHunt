"""Behavioral analysis for historical Windows telemetry.

This module intentionally focuses on behavioral deviations from user and host
baselines. It does not calculate risk scores or correlate unrelated events.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable


class BehavioralAnalyzer:
    """Identify unusual behavior using a historical baseline and a recent observation period."""

    OBSERVATION_DAYS = 10

    _SYSTEM_USERS = {
        "system",
        "nt authority\\system",
        "local service",
        "network service",
    }

    def __init__(self, events: Iterable[dict[str, Any]] | None = None):
        self.events = list(events) if events is not None else []
        self._all_events: list[dict[str, Any]] = []
        self._baseline_events: list[dict[str, Any]] = []
        self._observation_events: list[dict[str, Any]] = []
        self._dataset_start: datetime | None = None
        self._dataset_end: datetime | None = None
        self._observation_cutoff: datetime = datetime.utcnow()

        self._baseline_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._observation_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._baseline_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._observation_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._baseline_by_user_process: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        self._observation_by_user_process: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        self._baseline_by_user_command: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        self._observation_by_user_command: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)

        self._build_temporal_split()
        self._build_event_indexes()
        self.user_baselines = self.build_user_baselines()
        self.host_baselines = self.build_host_baselines()

    @staticmethod
    def _normalise_name(value: Any) -> str:
        if value is None:
            return ""
        return str(value).strip().lower()

    @staticmethod
    def _normalise_command(value: Any) -> str:
        if value is None:
            return ""
        text = str(value).strip().lower()
        return " ".join(text.replace("\r", " ").replace("\n", " ").split())

    @staticmethod
    def _is_user_account(value: Any) -> bool:
        if value is None:
            return False
        normalized = str(value).strip().lower()
        if not normalized:
            return False
        return normalized not in BehavioralAnalyzer._SYSTEM_USERS

    @staticmethod
    def _event_host(event: dict[str, Any]) -> str:
        host = event.get("host")
        if host is None:
            return ""
        return str(host).strip()

    @staticmethod
    def _event_process(event: dict[str, Any]) -> str:
        process_name = event.get("process")
        if process_name is None:
            return ""
        return str(process_name).strip()

    @staticmethod
    def _event_user(event: dict[str, Any]) -> str:
        user = event.get("user")
        if user is None:
            return ""
        return str(user).strip()

    @staticmethod
    def _parse_timestamp(value: Any) -> datetime | None:
        if value is None:
            return None

        text = str(value).strip()
        if not text:
            return None

        candidate = text
        if candidate.endswith("Z") or candidate.endswith("z"):
            candidate = f"{candidate[:-1]}+00:00"

        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            for fmt in (
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%d %H:%M:%S.%f",
            ):
                try:
                    parsed = datetime.strptime(candidate, fmt)
                    break
                except ValueError:
                    continue
            else:
                return None

        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        else:
            parsed = parsed.replace(tzinfo=timezone.utc).astimezone(timezone.utc).replace(tzinfo=None)
        return parsed

    def _sorted_events(self, events: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        def sort_key(event: dict[str, Any]) -> tuple[bool, datetime, str, str]:
            timestamp = self._parse_timestamp(event.get("timestamp"))
            return (
                timestamp is None,
                timestamp or datetime.min,
                str(event.get("event_uid") or ""),
                str(event.get("timestamp") or ""),
            )

        return sorted(events, key=sort_key)

    def _build_temporal_split(self) -> None:
        self._all_events = self._sorted_events(self.events)
        valid_timestamps = [self._parse_timestamp(event.get("timestamp")) for event in self._all_events]
        valid_timestamps = [value for value in valid_timestamps if value is not None]

        if not valid_timestamps:
            self._dataset_start = None
            self._dataset_end = None
            self._observation_cutoff = datetime.utcnow()
            self._baseline_events = []
            self._observation_events = []
            return

        self._dataset_start = min(valid_timestamps)
        self._dataset_end = max(valid_timestamps)
        self._observation_cutoff = self._dataset_end - timedelta(days=self.OBSERVATION_DAYS)

        self._baseline_events = [
            event
            for event in self._all_events
            if self._parse_timestamp(event.get("timestamp")) is not None and self._parse_timestamp(event.get("timestamp")) < self._observation_cutoff
        ]
        self._observation_events = [
            event
            for event in self._all_events
            if self._parse_timestamp(event.get("timestamp")) is not None and self._parse_timestamp(event.get("timestamp")) >= self._observation_cutoff
        ]

    def _build_event_indexes(self) -> None:
        self._baseline_by_user.clear()
        self._observation_by_user.clear()
        self._baseline_by_host.clear()
        self._observation_by_host.clear()
        self._baseline_by_user_process.clear()
        self._observation_by_user_process.clear()
        self._baseline_by_user_command.clear()
        self._observation_by_user_command.clear()

        for event in self._all_events:
            user = self._event_user(event)
            host = self._event_host(event)
            process_name = self._normalise_name(event.get("process"))
            command = self._normalise_command(event.get("command_line"))
            is_observation = self._parse_timestamp(event.get("timestamp")) is not None and self._parse_timestamp(event.get("timestamp")) >= self._observation_cutoff

            if user and self._is_user_account(user):
                target_user = self._observation_by_user if is_observation else self._baseline_by_user
                target_user[user].append(event)

                if process_name:
                    key = (user, process_name)
                    target_process = self._observation_by_user_process if is_observation else self._baseline_by_user_process
                    target_process[key].append(event)

                if command:
                    key = (user, command)
                    target_command = self._observation_by_user_command if is_observation else self._baseline_by_user_command
                    target_command[key].append(event)

            if host:
                target_host = self._observation_by_host if is_observation else self._baseline_by_host
                target_host[host].append(event)

    def _max_window_count(self, events: list[dict[str, Any]], minutes: int) -> tuple[int, list[dict[str, Any]]]:
        if not events:
            return 0, []

        sorted_events = sorted(events, key=lambda event: self._parse_timestamp(event.get("timestamp")) or datetime.min)
        best_count = 0
        best_cluster: list[dict[str, Any]] = []

        for start_index, start_event in enumerate(sorted_events):
            start_time = self._parse_timestamp(start_event.get("timestamp"))
            if start_time is None:
                continue

            cluster: list[dict[str, Any]] = []
            for event in sorted_events[start_index:]:
                event_time = self._parse_timestamp(event.get("timestamp"))
                if event_time is None:
                    continue
                if event_time - start_time <= timedelta(minutes=minutes):
                    cluster.append(event)
                else:
                    break

            if len(cluster) > best_count:
                best_count = len(cluster)
                best_cluster = cluster

        return best_count, best_cluster

    def build_user_baselines(self) -> dict[str, dict[str, Any]]:
        """Build historical user baselines using only events before the observation window."""
        baselines: dict[str, dict[str, Any]] = {}

        for user, events in sorted(self._baseline_by_user.items()):
            process_counts: Counter[str] = Counter()
            command_counts: Counter[str] = Counter()
            relationship_set: set[tuple[str, str]] = set()
            hour_counts: Counter[int] = Counter()
            hour_day_sets: dict[int, set[str]] = defaultdict(set)
            host_set: set[str] = set()
            historical_dates: set[str] = set()

            for event in events:
                if not (event.get("event_type") == "process" or event.get("process")):
                    continue

                process_name = self._normalise_name(event.get("process"))
                if process_name:
                    process_counts[process_name] += 1

                command = self._normalise_command(event.get("command_line"))
                if command:
                    command_counts[command] += 1

                parent = self._normalise_name(event.get("parent_process"))
                child = self._normalise_name(event.get("process"))
                if parent and child:
                    relationship_set.add((parent, child))

                timestamp = self._parse_timestamp(event.get("timestamp"))
                if timestamp is not None:
                    hour_counts[timestamp.hour] += 1
                    hour_day_sets[timestamp.hour].add(timestamp.date().isoformat())
                    historical_dates.add(timestamp.date().isoformat())

                host = self._event_host(event)
                if host:
                    host_set.add(host)

            hour_day_counts = {hour: len(days) for hour, days in sorted(hour_day_sets.items())}
            baselines[user] = {
                "process_counts": dict(sorted(process_counts.items(), key=lambda item: (-item[1], item[0]))),
                "known_processes": set(process_counts),
                "command_counts": dict(sorted(command_counts.items(), key=lambda item: (-item[1], item[0]))),
                "known_relationships": {f"{parent} -> {child}" for parent, child in relationship_set},
                "known_hosts": set(host_set),
                "active_hours": dict(sorted(hour_counts.items())),
                "hour_counts": dict(sorted(hour_counts.items())),
                "hour_day_counts": hour_day_counts,
                "historical_dates": sorted(historical_dates),
            }

        return baselines

    def build_host_baselines(self) -> dict[str, dict[str, Any]]:
        """Build historical host baselines using only baseline events."""
        baselines: dict[str, dict[str, Any]] = {}

        for host, events in sorted(self._baseline_by_host.items()):
            process_counts: Counter[str] = Counter()
            user_counts: Counter[str] = Counter()
            hour_counts: Counter[int] = Counter()

            for event in events:
                process_name = self._normalise_name(event.get("process"))
                if process_name:
                    process_counts[process_name] += 1

                user = self._event_user(event)
                if user:
                    user_counts[user] += 1

                timestamp = self._parse_timestamp(event.get("timestamp"))
                if timestamp is not None and (event.get("event_type") == "process" or event.get("process")):
                    hour_counts[timestamp.hour] += 1

            baselines[host] = {
                "historical_users": sorted(user_counts),
                "user_counts": dict(sorted(user_counts.items(), key=lambda item: (-item[1], item[0]))),
                "common_processes": dict(sorted(process_counts.items(), key=lambda item: (-item[1], item[0]))),
                "historical_active_hours": dict(sorted(hour_counts.items())),
            }

        return baselines

    def detect_after_hours_activity(self) -> list[dict[str, Any]]:
        """Flag process activity outside a user's historically normal hours."""
        findings: list[dict[str, Any]] = []

        for user, events in sorted(self._observation_by_user.items()):
            if not self._is_user_account(user):
                continue

            baseline = self.user_baselines.get(user, {})
            baseline_hour_day_counts = baseline.get("hour_day_counts", {})
            if not baseline_hour_day_counts:
                continue
            if sum(baseline.get("process_counts", {}).values()) < 10:
                continue

            normal_hours = {hour for hour, day_count in baseline_hour_day_counts.items() if day_count >= 2}
            if not normal_hours:
                normal_hours = set(baseline_hour_day_counts)

            by_hour: dict[int, list[dict[str, Any]]] = defaultdict(list)
            for event in events:
                if not (event.get("event_type") == "process" or event.get("process")):
                    continue
                timestamp = self._parse_timestamp(event.get("timestamp"))
                if timestamp is not None:
                    by_hour[timestamp.hour].append(event)

            for hour in sorted(by_hour):
                if hour in normal_hours:
                    continue
                representative = min(by_hour[hour], key=lambda event: self._parse_timestamp(event.get("timestamp")) or datetime.max)
                findings.append(
                    {
                        "finding_type": "after_hours_activity",
                        "severity": "medium",
                        "user": user,
                        "host": self._event_host(representative),
                        "timestamp": representative.get("timestamp"),
                        "description": (
                            f"{user} executed {self._event_process(representative) or 'a process'} during hour {hour:02d}, "
                            "outside historically normal activity hours."
                        ),
                        "evidence": {
                            "observed_hour": hour,
                            "normal_hours": sorted(normal_hours),
                            "historical_hour_counts": {str(key): value for key, value in sorted(baseline.get("hour_counts", {}).items())},
                            "historical_active_day_counts": {str(key): value for key, value in sorted(baseline_hour_day_counts.items())},
                            "process": self._event_process(representative),
                            "command_line": representative.get("command_line"),
                            "timestamp": representative.get("timestamp"),
                            "host": self._event_host(representative),
                        },
                    }
                )

        return sorted(
            findings,
            key=lambda item: (
                self._parse_timestamp(item.get("timestamp")) or datetime.min,
                item.get("user") or "",
                item.get("host") or "",
                item.get("finding_type") or "",
            ),
        )

    def detect_first_seen_process(self) -> list[dict[str, Any]]:
        """Flag a process not previously observed for that user in the historical baseline."""
        findings: list[dict[str, Any]] = []

        for user, events in sorted(self._observation_by_user.items()):
            if not self._is_user_account(user):
                continue

            baseline_processes = set(self.user_baselines.get(user, {}).get("known_processes", set()))
            seen: set[str] = set()
            for event in sorted(events, key=lambda item: self._parse_timestamp(item.get("timestamp")) or datetime.min):
                if not (event.get("event_type") == "process" or event.get("process")):
                    continue
                process_name = self._normalise_name(event.get("process"))
                if not process_name or process_name in baseline_processes or process_name in seen:
                    continue
                seen.add(process_name)
                findings.append(
                    {
                        "finding_type": "first_seen_process",
                        "severity": "medium",
                        "user": user,
                        "host": self._event_host(event),
                        "timestamp": event.get("timestamp"),
                        "description": (
                            f"{user} executed {process_name}, a process not previously observed in historical user activity."
                        ),
                        "evidence": {
                            "process": process_name,
                            "command_line": event.get("command_line"),
                            "path": event.get("path"),
                            "parent_process": event.get("parent_process"),
                            "historical_process_absence": True,
                            "first_observation_timestamp": event.get("timestamp"),
                            "host": self._event_host(event),
                        },
                    }
                )

        return sorted(
            findings,
            key=lambda item: (
                self._parse_timestamp(item.get("timestamp")) or datetime.min,
                item.get("user") or "",
                item.get("host") or "",
                item.get("finding_type") or "",
            ),
        )

    def detect_process_frequency_anomaly(self) -> list[dict[str, Any]]:
        """Flag a notable burst in a user/process pair compared with historical cadence."""
        findings: list[dict[str, Any]] = []

        for (user, process_name), events in sorted(self._observation_by_user_process.items()):
            if not self._is_user_account(user) or not process_name:
                continue
            if len(events) < 3:
                continue

            historical_events = self._baseline_by_user_process.get((user, process_name), [])
            historical_max_60, _ = self._max_window_count(historical_events, 60)
            cluster_size, cluster_events = self._max_window_count(events, 60)
            threshold = max(4, historical_max_60 * 2) if historical_max_60 else 4

            if cluster_size < threshold:
                continue

            anchor = min(cluster_events, key=lambda event: self._parse_timestamp(event.get("timestamp")) or datetime.max)
            findings.append(
                {
                    "finding_type": "process_frequency_anomaly",
                    "severity": "high" if cluster_size >= 6 else "medium",
                    "user": user,
                    "host": self._event_host(anchor),
                    "timestamp": anchor.get("timestamp"),
                    "description": (
                        f"{user} executed {process_name} {cluster_size} times within a 60-minute period, a notable increase over prior cadence."
                    ),
                    "evidence": {
                        "process": process_name,
                        "window_minutes": 60,
                        "cluster_size": cluster_size,
                        "cluster_timestamps": [
                            event.get("timestamp")
                            for event in sorted(cluster_events, key=lambda item: self._parse_timestamp(item.get("timestamp")) or datetime.min)
                        ],
                        "historical_comparable_count": historical_max_60,
                        "comparison_threshold": threshold,
                    },
                }
            )

        return sorted(
            findings,
            key=lambda item: (
                self._parse_timestamp(item.get("timestamp")) or datetime.min,
                item.get("user") or "",
                item.get("host") or "",
                item.get("finding_type") or "",
            ),
        )

    def detect_new_process_relationship(self) -> list[dict[str, Any]]:
        """Flag a parent-child relationship that did not appear in the user's historical baseline."""
        findings: list[dict[str, Any]] = []

        for user, events in sorted(self._observation_by_user.items()):
            if not self._is_user_account(user):
                continue

            baseline_pairs = set(self.user_baselines.get(user, {}).get("known_relationships", set()))
            seen_pairs: set[str] = set()

            for event in sorted(events, key=lambda item: self._parse_timestamp(item.get("timestamp")) or datetime.min):
                if not (event.get("event_type") == "process" or event.get("process")):
                    continue
                parent = self._normalise_name(event.get("parent_process"))
                child = self._normalise_name(event.get("process"))
                if not parent or not child:
                    continue
                pair = f"{parent} -> {child}"
                if pair in seen_pairs or pair in baseline_pairs:
                    continue
                seen_pairs.add(pair)
                findings.append(
                    {
                        "finding_type": "new_process_relationship",
                        "severity": "medium",
                        "user": user,
                        "host": self._event_host(event),
                        "timestamp": event.get("timestamp"),
                        "description": (
                            f"{user} performed {parent} -> {child}, a parent-child relationship not previously observed in historical activity."
                        ),
                        "evidence": {
                            "parent_process": parent,
                            "child_process": child,
                            "command_line": event.get("command_line"),
                            "path": event.get("path"),
                            "timestamp": event.get("timestamp"),
                            "host": self._event_host(event),
                            "historical_relationship_evidence": sorted(baseline_pairs),
                        },
                    }
                )

        return sorted(
            findings,
            key=lambda item: (
                self._parse_timestamp(item.get("timestamp")) or datetime.min,
                item.get("user") or "",
                item.get("host") or "",
                item.get("finding_type") or "",
            ),
        )

    def detect_host_deviation(self) -> list[dict[str, Any]]:
        """Flag a host that was not used by a user in their historical baseline."""
        findings: list[dict[str, Any]] = []

        for user, events in sorted(self._observation_by_user.items()):
            if not self._is_user_account(user):
                continue

            baseline_hosts = set(self.user_baselines.get(user, {}).get("known_hosts", set()))
            observed_hosts: set[str] = set()

            for event in sorted(events, key=lambda item: self._parse_timestamp(item.get("timestamp")) or datetime.min):
                host = self._event_host(event)
                if not host or host in baseline_hosts or host in observed_hosts:
                    continue
                observed_hosts.add(host)
                findings.append(
                    {
                        "finding_type": "host_deviation",
                        "severity": "medium",
                        "user": user,
                        "host": host,
                        "timestamp": event.get("timestamp"),
                        "description": (
                            f"{user} was active on {host}, a host not previously observed in historical activity."
                        ),
                        "evidence": {
                            "user": user,
                            "observed_host": host,
                            "historical_known_hosts": sorted(baseline_hosts),
                            "timestamp": event.get("timestamp"),
                            "event_type": event.get("event_type"),
                            "process": event.get("process"),
                            "command_line": event.get("command_line"),
                        },
                    }
                )

        return sorted(
            findings,
            key=lambda item: (
                self._parse_timestamp(item.get("timestamp")) or datetime.min,
                item.get("user") or "",
                item.get("host") or "",
                item.get("finding_type") or "",
            ),
        )

    def detect_burst_activity(self) -> list[dict[str, Any]]:
        """Flag repeated execution of the same normalized command line in a short observation window."""
        findings: list[dict[str, Any]] = []

        for (user, command), events in sorted(self._observation_by_user_command.items()):
            if not self._is_user_account(user) or not command:
                continue
            if len(events) < 3:
                continue

            historical_events = self._baseline_by_user_command.get((user, command), [])
            historical_max_30, _ = self._max_window_count(historical_events, 30)
            cluster_size, cluster_events = self._max_window_count(events, 30)
            threshold = max(4, historical_max_30 * 2) if historical_max_30 else 4

            if cluster_size < threshold:
                continue

            anchor = min(cluster_events, key=lambda event: self._parse_timestamp(event.get("timestamp")) or datetime.max)
            findings.append(
                {
                    "finding_type": "burst_activity",
                    "severity": "high" if cluster_size >= 4 else "medium",
                    "user": user,
                    "host": self._event_host(anchor),
                    "timestamp": anchor.get("timestamp"),
                    "description": (
                        f"{user} executed the same command ({command}) {cluster_size} times in a 30-minute window, a notable increase over prior cadence."
                    ),
                    "evidence": {
                        "normalized_command": command,
                        "process": anchor.get("process"),
                        "cluster_size": cluster_size,
                        "cluster_timestamps": [
                            event.get("timestamp")
                            for event in sorted(cluster_events, key=lambda item: self._parse_timestamp(item.get("timestamp")) or datetime.min)
                        ],
                        "window_minutes": 30,
                        "historical_comparable_count": historical_max_30,
                        "comparison_threshold": threshold,
                    },
                }
            )

        return sorted(
            findings,
            key=lambda item: (
                self._parse_timestamp(item.get("timestamp")) or datetime.min,
                item.get("user") or "",
                item.get("host") or "",
                item.get("finding_type") or "",
            ),
        )

    def analyze(self) -> list[dict[str, Any]]:
        """Return a deterministic, chronological view of meaningful deviations."""
        findings: list[dict[str, Any]] = []
        findings.extend(self.detect_after_hours_activity())
        findings.extend(self.detect_first_seen_process())
        findings.extend(self.detect_process_frequency_anomaly())
        findings.extend(self.detect_new_process_relationship())
        findings.extend(self.detect_host_deviation())
        findings.extend(self.detect_burst_activity())

        return sorted(
            findings,
            key=lambda item: (
                self._parse_timestamp(item.get("timestamp")) or datetime.min,
                item.get("finding_type") or "",
                item.get("user") or "",
                item.get("host") or "",
            ),
        )
