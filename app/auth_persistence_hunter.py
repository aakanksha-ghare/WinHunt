"""Authentication and persistence hunting for Windows telemetry."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Mapping


AUTH_EVENT_IDS = {
    4624: "successful_logon",
    4625: "failed_logon",
    4648: "explicit_credential_use",
    4672: "special_privileges_assigned",
    4771: "kerberos_pre_auth_failure",
    4740: "account_lockout",
    4720: "user_account_created",
    4726: "user_account_deleted",
    4732: "local_group_membership_changed",
    4698: "scheduled_task_created",
    4702: "scheduled_task_updated",
    7045: "service_installed",
    11: "file_created",
    12: "registry_object_create_delete",
    13: "registry_value_set",
}

RUN_KEY_SUFFIXES = (
    "software\\microsoft\\windows\\currentversion\\run",
    "software\\microsoft\\windows\\currentversion\\runonce",
)


def _as_event_list(events: Any) -> list[dict[str, Any]]:
    if events is None:
        return []
    if isinstance(events, Mapping):
        return [dict(events)]
    if isinstance(events, Iterable):
        normalized: list[dict[str, Any]] = []
        for item in events:
            if isinstance(item, Mapping):
                normalized.append(dict(item))
        return normalized
    return []


def _event_value(event: Mapping[str, Any], *names: str) -> Any:
    for name in names:
        if name in event and event.get(name) is not None:
            return event.get(name)
    return None


def _normalize_event_id(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.isdigit():
            try:
                return int(text)
            except ValueError:
                return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _normalize_event_type(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _normalize_username(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _extract_user(event: Mapping[str, Any]) -> str:
    for name in (
        "user",
        "username",
        "target_user",
        "target_username",
        "account_name",
        "subject_user",
        "subjectusername",
        "account",
    ):
        value = _event_value(event, name)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _extract_process(event: Mapping[str, Any]) -> str:
    for name in ("process", "process_name", "image"):
        value = _event_value(event, name)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _extract_command_line(event: Mapping[str, Any]) -> str:
    for name in ("command_line", "command", "process_command_line"):
        value = _event_value(event, name)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _extract_path(event: Mapping[str, Any]) -> str:
    for name in ("path", "file_path", "target_filename", "target_object", "image"):
        value = _event_value(event, name)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _extract_source_ip(event: Mapping[str, Any]) -> str:
    for name in ("source_ip", "src_ip", "ip"):
        value = _event_value(event, name)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _extract_target_user(event: Mapping[str, Any]) -> str:
    for name in ("target_user", "target_username", "account_name", "new_account", "member_name"):
        value = _event_value(event, name)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _extract_registry_path(event: Mapping[str, Any]) -> str:
    for name in ("registry_path", "registry_key", "target_object", "target_object_name", "key"):
        value = _event_value(event, name)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _extract_service_name(event: Mapping[str, Any]) -> str:
    for name in ("service_name", "service"):
        value = _event_value(event, name)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _extract_task_name(event: Mapping[str, Any]) -> str:
    value = _event_value(event, "task_name")
    if value is not None and str(value).strip():
        return str(value)
    return ""


def _extract_group_name(event: Mapping[str, Any]) -> str:
    for name in ("group_name", "group", "target_group"):
        value = _event_value(event, name)
        if value is not None and str(value).strip():
            return str(value)
    return ""


def _parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if not isinstance(value, str):
        try:
            return _parse_timestamp(str(value))
        except Exception:
            return None

    text = str(value).strip()
    if not text:
        return None
    candidate = text
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    if candidate.endswith(" UTC"):
        candidate = candidate[:-4] + "+00:00"
    if ("T" not in candidate) and (" " in candidate):
        candidate = candidate.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError:
        for pattern in ( "%Y-%m-%d %H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z" ):
            try:
                dt = datetime.strptime(candidate, pattern)
                break
            except ValueError:
                dt = None
        else:
            return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt


def _canonicalize_path(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().replace("/", "\\")
    text = text.replace("HKEY_CURRENT_USER", "HKCU").replace("HKEY_LOCAL_MACHINE", "HKLM")
    return text.lower()


def _looks_like_run_key(value: Any) -> bool:
    path = _canonicalize_path(value)
    if not path:
        return False
    patterns = (
        r"(^|\\)(hkcu|hklm)\\software\\microsoft\\windows\\currentversion\\run(?:once)?$",
        r"(^|\\)(hkcu|hklm)\\software\\microsoft\\windows\\currentversion\\run(?:once)?\\.+",
        r"(^|\\)(hkey_current_user|hkey_local_machine)\\software\\microsoft\\windows\\currentversion\\run(?:once)?$",
        r"(^|\\)(hkey_current_user|hkey_local_machine)\\software\\microsoft\\windows\\currentversion\\run(?:once)?\\.+",
    )
    return any(re.search(pattern, path) for pattern in patterns)


def _looks_like_startup_folder(value: Any) -> bool:
    path = _canonicalize_path(value)
    if not path:
        return False
    if "start menu\\programs\\startup" in path:
        return True
    if "microsoft\\windows\\start menu\\programs\\startup" in path:
        return True
    return False


def _event_uid(event: Mapping[str, Any]) -> str:
    uid = _event_value(event, "event_uid", "uid")
    if uid is not None and str(uid).strip():
        return f"event_uid:{uid}"

    event_id = _normalize_event_id(_event_value(event, "event_id", "EventID", "eventId"))
    timestamp = _event_value(event, "timestamp", "time", "event_time")
    user = _extract_user(event)
    host = _event_value(event, "host", "hostname", "computer_name")
    key = _event_value(event, "target_object", "registry_path", "path", "file_path", "service_name", "task_name", "target_user")
    return "|".join(
        [
            "event",
            str(event_id or ""),
            str(timestamp or ""),
            str(user or ""),
            str(host or ""),
            str(key or ""),
        ]
    )


def _serialize_evidence(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_serialize_evidence(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _serialize_evidence(v) for k, v in value.items()}
    return str(value)


def _make_finding(*, finding_type: str, severity: str, user: Any, host: Any, timestamp: Any, description: str, evidence: dict[str, Any]) -> dict[str, Any]:
    normalized_user = user if user is not None else ""
    normalized_host = host if host is not None else ""
    return {
        "finding_type": finding_type,
        "severity": severity,
        "user": str(normalized_user),
        "host": str(normalized_host),
        "timestamp": timestamp,
        "description": description,
        "evidence": {str(key): _serialize_evidence(value) for key, value in evidence.items() if value is not None},
    }


def _dedupe_findings(findings: Iterable[dict[str, Any]], source_events: Mapping[str, Mapping[str, Any]] | None = None) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for finding in findings:
        key = str(finding.get("finding_type") or "")
        timestamp = str(finding.get("timestamp") or "")
        user = str(finding.get("user") or "")
        host = str(finding.get("host") or "")
        evidence = finding.get("evidence") or {}
        fallback = "|".join([key, timestamp, user, host, str(evidence)])
        dedupe_key = fallback
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        deduped.append(finding)
    return deduped


class AuthPersistenceHunter:
    """In-memory authentication and persistence hunter."""

    def __init__(self, events: Any | None = None):
        raw_events = _as_event_list(events)
        indexed: list[tuple[datetime | None, dict[str, Any]]] = []
        self.events: list[dict[str, Any]] = []
        self._events_by_id: dict[int, list[dict[str, Any]]] = defaultdict(list)
        self._events_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._events_by_host: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._events_by_type: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._auth_events_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
        self._sorted_events: list[dict[str, Any]] = []

        for item in raw_events:
            event = dict(item)
            self.events.append(event)
            dt = _parse_timestamp(_event_value(event, "timestamp", "time", "event_time"))
            indexed.append((dt, event))
            event_id = _normalize_event_id(_event_value(event, "event_id", "EventID", "eventId"))
            if event_id is not None:
                self._events_by_id[event_id].append(event)
            event_type = _normalize_event_type(_event_value(event, "event_type", "type", "eventType"))
            if event_type:
                self._events_by_type[event_type].append(event)
            host = _event_value(event, "host", "hostname", "computer_name")
            if host is not None and str(host).strip():
                self._events_by_host[str(host).strip()].append(event)
            user = _extract_user(event)
            normalized_user = _normalize_username(user)
            if normalized_user:
                self._events_by_user[normalized_user].append(event)
                if event_id in AUTH_EVENT_IDS or event_type in {"failed_logon", "success_logon", "scheduled_task", "registry_value_set", "registry_object_create_delete", "file_created", "service_installed"}:
                    self._auth_events_by_user[normalized_user].append(event)

        self._sorted_events = [event for _, event in sorted(indexed, key=lambda pair: (pair[0] is None, pair[0] or datetime.min.replace(tzinfo=timezone.utc), _normalize_event_type(_event_value(pair[1], "event_type", "type", "eventType"))))]

    def _iter_events_by_id(self, *event_ids: int) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for event_id in event_ids:
            result.extend(self._events_by_id.get(event_id, []))
        return result

    def _event_sort_key(self, event: Mapping[str, Any]) -> datetime:
        dt = _parse_timestamp(_event_value(event, "timestamp", "time", "event_time"))
        if dt is None:
            return datetime.min.replace(tzinfo=timezone.utc)
        return dt

    def _event_identity(self, event: Mapping[str, Any]) -> str:
        return _event_uid(event)

    def detect_failed_login_bursts(self) -> list[dict[str, Any]]:
        failures_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in self._sorted_events:
            event_id = _normalize_event_id(_event_value(event, "event_id", "EventID", "eventId"))
            if event_id not in {4625, 4771}:
                continue
            user = _extract_user(event) or _extract_target_user(event)
            normalized = _normalize_username(user)
            if not normalized:
                normalized = "unknown"
            failures_by_user[normalized].append(event)

        findings: list[dict[str, Any]] = []
        for user_key, events in failures_by_user.items():
            ordered = sorted(events, key=self._event_sort_key)
            start = 0
            while start < len(ordered):
                end = start
                start_dt = self._event_sort_key(ordered[start])
                while end < len(ordered) and (self._event_sort_key(ordered[end]) - start_dt).total_seconds() <= 600:
                    end += 1
                burst_events = ordered[start:end]
                if len(burst_events) >= 5:
                    failure_count = len(burst_events)
                    first_dt = self._event_sort_key(burst_events[0])
                    host_values = [str(_event_value(item, "host", "hostname", "computer_name") or "") for item in burst_events]
                    source_ips = [str(_extract_source_ip(item) or "") for item in burst_events]
                    account_value = _extract_user(burst_events[0]) or _extract_target_user(burst_events[0]) or user_key
                    finding = _make_finding(
                        finding_type="failed_login_burst",
                        severity="medium",
                        user=account_value,
                        host=host_values[0] if host_values else "",
                        timestamp=first_dt.isoformat().replace("+00:00", "Z"),
                        description=f"{failure_count} failed logons occurred within 10 minutes for account {account_value}.",
                        evidence={
                            "account": account_value,
                            "failure_count": failure_count,
                            "event_ids": [_normalize_event_id(_event_value(item, "event_id", "EventID", "eventId")) for item in burst_events],
                            "timestamps": [str(_event_value(item, "timestamp", "time", "event_time") or "") for item in burst_events],
                            "hosts": [str(_event_value(item, "host", "hostname", "computer_name") or "") for item in burst_events],
                            "source_ips": [str(_extract_source_ip(item) or "") for item in burst_events],
                        },
                    )
                    findings.append(finding)
                    start = end
                else:
                    start += 1

        return _dedupe_findings(findings)

    def detect_failure_then_success(self) -> list[dict[str, Any]]:
        failures_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
        successes_by_user: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for event in self._sorted_events:
            event_id = _normalize_event_id(_event_value(event, "event_id", "EventID", "eventId"))
            user = _extract_user(event) or _extract_target_user(event)
            normalized = _normalize_username(user)
            if not normalized:
                normalized = "unknown"
            if event_id == 4625:
                failures_by_user[normalized].append(event)
            elif event_id == 4624:
                successes_by_user[normalized].append(event)

        findings: list[dict[str, Any]] = []
        for user_key, successes in successes_by_user.items():
            ordered_failures = sorted(failures_by_user.get(user_key, []), key=self._event_sort_key)
            for success in sorted(successes, key=self._event_sort_key):
                success_dt = self._event_sort_key(success)
                failure_window = []
                for failure in ordered_failures:
                    failure_dt = self._event_sort_key(failure)
                    if success_dt - failure_dt <= timedelta(minutes=15) and failure_dt <= success_dt:
                        failure_window.append(failure)
                if len(failure_window) < 3:
                    continue
                account_value = _extract_user(success) or _extract_target_user(success) or user_key
                evidence = {
                    "failure_count": len(failure_window),
                    "failure_timestamps": [str(_event_value(item, "timestamp", "time", "event_time") or "") for item in failure_window],
                    "success_timestamp": _event_value(success, "timestamp", "time", "event_time"),
                    "account": account_value,
                    "hosts": [str(_event_value(item, "host", "hostname", "computer_name") or "") for item in failure_window + [success]],
                    "source_ips": [str(_extract_source_ip(item) or "") for item in failure_window + [success]],
                    "event_ids": [
                        _normalize_event_id(_event_value(item, "event_id", "EventID", "eventId"))
                        for item in failure_window + [success]
                    ],
                }
                findings.append(
                    _make_finding(
                        finding_type="failure_then_success",
                        severity="medium",
                        user=account_value,
                        host=str(_event_value(success, "host", "hostname", "computer_name") or ""),
                        timestamp=_event_value(success, "timestamp", "time", "event_time"),
                        description=f"{len(failure_window)} authentication failures preceded a successful logon for account {account_value}.",
                        evidence=evidence,
                    )
                )

        return _dedupe_findings(findings)

    def detect_explicit_credentials(self) -> list[dict[str, Any]]:
        events = self._events_by_id.get(4648, [])
        findings: list[dict[str, Any]] = []
        for event in sorted(events, key=self._event_sort_key):
            user = _extract_user(event) or _extract_target_user(event) or ""
            target = _extract_target_user(event)
            process = _extract_process(event)
            host = _event_value(event, "host", "hostname", "computer_name")
            timestamp = _event_value(event, "timestamp", "time", "event_time")
            findings.append(
                _make_finding(
                    finding_type="explicit_credential_use",
                    severity="medium",
                    user=user,
                    host=str(host or ""),
                    timestamp=timestamp,
                    description="Explicit credentials were used for a logon or network operation.",
                    evidence={
                        "user": user,
                        "target_user": target,
                        "target_host": _event_value(event, "target_host", "hostname", "computer_name"),
                        "process": process,
                        "command_line": _extract_command_line(event),
                        "event_id": 4648,
                        "timestamp": timestamp,
                    },
                )
            )
        return _dedupe_findings(findings)

    def detect_privileged_logons(self) -> list[dict[str, Any]]:
        events = self._events_by_id.get(4672, [])
        findings: list[dict[str, Any]] = []
        for event in sorted(events, key=self._event_sort_key):
            user = _extract_user(event) or ""
            findings.append(
                _make_finding(
                    finding_type="privileged_logon",
                    severity="medium",
                    user=user,
                    host=str(_event_value(event, "host", "hostname", "computer_name") or ""),
                    timestamp=_event_value(event, "timestamp", "time", "event_time"),
                    description="A privileged logon was observed.",
                    evidence={
                        "user": user,
                        "host": _event_value(event, "host", "hostname", "computer_name"),
                        "privileges": _event_value(event, "privileges", "privilege_list", "privilege"),
                        "logon_id": _event_value(event, "logon_id", "logonId", "subject_logon_id"),
                        "timestamp": _event_value(event, "timestamp", "time", "event_time"),
                        "event_id": 4672,
                    },
                )
            )
        return _dedupe_findings(findings)

    def detect_account_lockouts(self) -> list[dict[str, Any]]:
        events = self._events_by_id.get(4740, [])
        findings: list[dict[str, Any]] = []
        for event in sorted(events, key=self._event_sort_key):
            account = _extract_target_user(event) or _extract_user(event) or ""
            findings.append(
                _make_finding(
                    finding_type="account_lockout",
                    severity="medium",
                    user=account,
                    host=str(_event_value(event, "host", "hostname", "computer_name") or ""),
                    timestamp=_event_value(event, "timestamp", "time", "event_time"),
                    description=f"Account {account} was locked out.",
                    evidence={
                        "account": account,
                        "host": _event_value(event, "host", "hostname", "computer_name"),
                        "source_workstation": _event_value(event, "workstation_name", "source_workstation", "caller_computer_name"),
                        "timestamp": _event_value(event, "timestamp", "time", "event_time"),
                        "event_id": 4740,
                    },
                )
            )
        return _dedupe_findings(findings)

    def detect_new_accounts(self) -> list[dict[str, Any]]:
        events = self._events_by_id.get(4720, [])
        findings: list[dict[str, Any]] = []
        for event in sorted(events, key=self._event_sort_key):
            new_account = _extract_target_user(event) or _event_value(event, "new_account") or ""
            creator = _extract_user(event) or _event_value(event, "subject_user") or ""
            findings.append(
                _make_finding(
                    finding_type="new_account_created",
                    severity="medium",
                    user=creator or new_account,
                    host=str(_event_value(event, "host", "hostname", "computer_name") or ""),
                    timestamp=_event_value(event, "timestamp", "time", "event_time"),
                    description=f"Account {new_account} was created.",
                    evidence={
                        "new_account": new_account,
                        "creator": creator,
                        "host": _event_value(event, "host", "hostname", "computer_name"),
                        "timestamp": _event_value(event, "timestamp", "time", "event_time"),
                        "event_id": 4720,
                    },
                )
            )
        return _dedupe_findings(findings)

    def detect_local_group_membership_changes(self) -> list[dict[str, Any]]:
        events = self._events_by_id.get(4732, [])
        findings: list[dict[str, Any]] = []
        for event in sorted(events, key=self._event_sort_key):
            member = _extract_target_user(event) or _event_value(event, "member_name", "member") or ""
            group = _extract_group_name(event) or _event_value(event, "target_group") or ""
            actor = _extract_user(event) or _event_value(event, "subject_user") or ""
            findings.append(
                _make_finding(
                    finding_type="local_group_membership_change",
                    severity="medium",
                    user=actor or member,
                    host=str(_event_value(event, "host", "hostname", "computer_name") or ""),
                    timestamp=_event_value(event, "timestamp", "time", "event_time"),
                    description=f"Member {member} was added to local group {group}.",
                    evidence={
                        "member": member,
                        "group": group,
                        "actor": actor,
                        "host": _event_value(event, "host", "hostname", "computer_name"),
                        "timestamp": _event_value(event, "timestamp", "time", "event_time"),
                        "event_id": 4732,
                    },
                )
            )
        return _dedupe_findings(findings)

    def detect_scheduled_task_persistence(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for event_id in (4698, 4702):
            events.extend(self._events_by_id.get(event_id, []))
        for event in self._sorted_events:
            event_id = _normalize_event_id(_event_value(event, "event_id", "EventID", "eventId"))
            event_type = _normalize_event_type(_event_value(event, "event_type", "type", "eventType"))
            if event_id is None and event_type == "scheduled_task":
                events.append(event)

        findings: list[dict[str, Any]] = []
        seen: set[str] = set()
        for event in sorted(events, key=self._event_sort_key):
            event_uid = self._event_identity(event)
            if event_uid in seen:
                continue
            seen.add(event_uid)
            event_id = _normalize_event_id(_event_value(event, "event_id", "EventID", "eventId"))
            task_name = _extract_task_name(event)
            command = _event_value(event, "action", "command", "command_line")
            user = _extract_user(event) or _event_value(event, "author") or ""
            findings.append(
                _make_finding(
                    finding_type="scheduled_task_persistence",
                    severity="medium",
                    user=user,
                    host=str(_event_value(event, "host", "hostname", "computer_name") or ""),
                    timestamp=_event_value(event, "timestamp", "time", "event_time"),
                    description=f"Scheduled task {task_name or 'unknown'} was created or updated.",
                    evidence={
                        "task_name": task_name,
                        "action": command,
                        "user": user,
                        "host": _event_value(event, "host", "hostname", "computer_name"),
                        "timestamp": _event_value(event, "timestamp", "time", "event_time"),
                        "event_id": event_id,
                    },
                )
            )
        return _dedupe_findings(findings)

    def detect_registry_run_key_persistence(self) -> list[dict[str, Any]]:
        events = []
        for event_id in (12, 13):
            events.extend(self._events_by_id.get(event_id, []))
        findings: list[dict[str, Any]] = []
        for event in sorted(events, key=self._event_sort_key):
            registry_value = _extract_registry_path(event)
            if not _looks_like_run_key(registry_value):
                continue
            user = _extract_user(event) or ""
            value_name = _event_value(event, "value_name", "reg_value_name", "key_name")
            value_data = _event_value(event, "value_data", "data", "details", "value")
            findings.append(
                _make_finding(
                    finding_type="registry_run_key_persistence",
                    severity="medium",
                    user=user,
                    host=str(_event_value(event, "host", "hostname", "computer_name") or ""),
                    timestamp=_event_value(event, "timestamp", "time", "event_time"),
                    description="A Windows Run or RunOnce registry value was modified.",
                    evidence={
                        "registry_path": registry_value,
                        "value_name": value_name,
                        "value_data": value_data,
                        "user": user,
                        "host": _event_value(event, "host", "hostname", "computer_name"),
                        "timestamp": _event_value(event, "timestamp", "time", "event_time"),
                        "event_id": _normalize_event_id(_event_value(event, "event_id", "EventID", "eventId")),
                    },
                )
            )
        return _dedupe_findings(findings)

    def detect_startup_persistence(self) -> list[dict[str, Any]]:
        events = self._events_by_id.get(11, [])
        findings: list[dict[str, Any]] = []
        for event in sorted(events, key=self._event_sort_key):
            file_path = _extract_path(event)
            if not _looks_like_startup_folder(file_path):
                continue
            user = _extract_user(event) or ""
            findings.append(
                _make_finding(
                    finding_type="startup_persistence",
                    severity="medium",
                    user=user,
                    host=str(_event_value(event, "host", "hostname", "computer_name") or ""),
                    timestamp=_event_value(event, "timestamp", "time", "event_time"),
                    description="A file created in a Windows Startup folder was observed.",
                    evidence={
                        "path": file_path,
                        "user": user,
                        "host": _event_value(event, "host", "hostname", "computer_name"),
                        "timestamp": _event_value(event, "timestamp", "time", "event_time"),
                        "event_id": 11,
                    },
                )
            )
        return _dedupe_findings(findings)

    def detect_service_installation(self) -> list[dict[str, Any]]:
        events = self._events_by_id.get(7045, [])
        findings: list[dict[str, Any]] = []
        for event in sorted(events, key=self._event_sort_key):
            service_name = _extract_service_name(event)
            executable = _event_value(event, "image", "path", "service_executable", "service_path")
            account = _event_value(event, "service_account", "service_logon_account")
            severity = "medium"
            if executable and isinstance(executable, str) and ("\\system32\\" in executable.lower() or "\\drivers\\" in executable.lower()):
                severity = "high"
            findings.append(
                _make_finding(
                    finding_type="service_installation",
                    severity=severity,
                    user=str(_extract_user(event) or ""),
                    host=str(_event_value(event, "host", "hostname", "computer_name") or ""),
                    timestamp=_event_value(event, "timestamp", "time", "event_time"),
                    description=f"Windows service {service_name or 'unknown'} was installed.",
                    evidence={
                        "service_name": service_name,
                        "image": executable,
                        "service_account": account,
                        "host": _event_value(event, "host", "hostname", "computer_name"),
                        "timestamp": _event_value(event, "timestamp", "time", "event_time"),
                        "event_id": 7045,
                    },
                )
            )
        return _dedupe_findings(findings)

    def analyze(self) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for detector_name in (
            "detect_failed_login_bursts",
            "detect_failure_then_success",
            "detect_explicit_credentials",
            "detect_privileged_logons",
            "detect_account_lockouts",
            "detect_new_accounts",
            "detect_local_group_membership_changes",
            "detect_scheduled_task_persistence",
            "detect_registry_run_key_persistence",
            "detect_startup_persistence",
            "detect_service_installation",
        ):
            detector = getattr(self, detector_name)
            findings.extend(detector())

        findings = _dedupe_findings(findings)
        return sorted(
            findings,
            key=lambda item: (
                _parse_timestamp(item.get("timestamp")) or datetime.min.replace(tzinfo=timezone.utc),
                str(item.get("finding_type") or ""),
                str(item.get("user") or ""),
                str(item.get("host") or ""),
            ),
        )

    def hunt(self) -> list[dict[str, Any]]:
        return self.analyze()


def detect_auth_persistence(event: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(event, Mapping):
        return None
    findings = AuthPersistenceHunter([event]).analyze()
    if not findings:
        return None
    return findings[0]


def hunt_auth_persistence(events: Any) -> list[dict[str, Any]]:
    return AuthPersistenceHunter(events).analyze()


def detect_auth_persistence_events(events: Any) -> list[dict[str, Any]]:
    return hunt_auth_persistence(events)


def scan_auth_persistence(events: Any) -> list[dict[str, Any]]:
    return hunt_auth_persistence(events)


__all__ = [
    "AuthPersistenceHunter",
    "detect_auth_persistence",
    "detect_auth_persistence_events",
    "hunt_auth_persistence",
    "scan_auth_persistence",
]
