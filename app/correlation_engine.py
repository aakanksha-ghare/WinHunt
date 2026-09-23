from __future__ import annotations

import copy
import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Optional

DEFAULT_CORRELATION_WINDOW_MINUTES = 30
DEFAULT_WEAK_HOST_WINDOW_MINUTES = 10

__all__ = [
    "EventCorrelator",
    "correlate_findings",
    "build_attack_chains",
    "DEFAULT_CORRELATION_WINDOW_MINUTES",
    "DEFAULT_WEAK_HOST_WINDOW_MINUTES",
]


def _has_non_empty_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def _field_value(record: dict[str, Any], *aliases: str) -> Any:
    if not isinstance(record, dict):
        return None
    for key in aliases:
        value = record.get(key)
        if _has_non_empty_value(value):
            return value
    evidence = record.get("evidence") if isinstance(record.get("evidence"), dict) else {}
    for key in aliases:
        value = evidence.get(key)
        if _has_non_empty_value(value):
            return value
    return None


def _field_value_str(record: dict[str, Any], *aliases: str) -> Optional[str]:
    value = _field_value(record, *aliases)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _normalize_process_name(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()


def _json_safe(value: Any) -> Any:
    """Convert arbitrary objects into JSON-safe values."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _normalize_host(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


def _normalize_user(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


def _derive_stage(finding_type: Any) -> str:
    name = str(finding_type or "unknown").strip().lower()
    mapping = {
        "encoded_powershell": "execution",
        "office_to_powershell": "execution",
        "suspicious_executable_location": "execution",
        "failed_login_burst": "authentication",
        "failure_then_success": "authentication",
        "explicit_credential_use": "authentication",
        "privileged_logon": "authentication",
        "account_lockout": "authentication",
        "new_account_created": "account",
        "local_group_membership_change": "account",
        "scheduled_task_persistence": "persistence",
        "registry_run_key_persistence": "persistence",
        "startup_persistence": "persistence",
        "service_installation": "persistence",
        "after_hours": "behavioral",
        "after_hours_activity": "behavioral",
        "first_seen_process": "behavioral",
        "process_frequency_anomaly": "behavioral",
        "new_process_relationship": "behavioral",
        "host_deviation": "behavioral",
        "burst_activity": "behavioral",
    }
    return mapping.get(name, "other")


def _safe_isoformat(value: Any) -> Optional[str]:
    if value is None:
        return None
    ts = _parse_timestamp(value)
    if ts is None:
        return None
    return ts.astimezone(timezone.utc).isoformat()


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        try:
            dt = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            try:
                dt = datetime.strptime(text, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
    else:
        return None

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _stable_finding_id(finding: dict[str, Any]) -> str:
    candidates = [
        finding.get("event_uid"),
        finding.get("eventUid"),
        finding.get("uid"),
        finding.get("finding_uid"),
        finding.get("findingUid"),
        finding.get("id"),
    ]
    for value in candidates:
        if value is not None and str(value).strip():
            return f"uid:{str(value)}"

    payload = {
        "type": str(finding.get("finding_type") or "unknown"),
        "timestamp": _safe_isoformat(finding.get("timestamp")),
        "user": _normalize_user(finding.get("user")),
        "host": _normalize_host(finding.get("host")),
        "evidence": _json_safe(finding.get("evidence") or {}),
    }
    return "derived:" + json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _coerce_findings(findings: Any) -> list[dict[str, Any]]:
    if findings is None:
        return []
    if isinstance(findings, dict):
        entries = [findings]
    elif isinstance(findings, Iterable):
        entries = list(findings)
    else:
        return []

    results: list[dict[str, Any]] = []
    for item in entries:
        if not isinstance(item, dict):
            continue
        if not any(
            [
                item.get("finding_type"),
                item.get("host"),
                item.get("user"),
                item.get("timestamp"),
                item.get("description"),
                item.get("evidence"),
            ]
        ):
            continue
        source = copy.deepcopy(item)
        evidence = source.get("evidence")
        if evidence is None:
            evidence = {}
        source["evidence"] = _json_safe(evidence)
        source["host"] = source.get("host")
        source["user"] = source.get("user")
        source["finding_type"] = source.get("finding_type") or "unknown"
        source["timestamp"] = source.get("timestamp")
        source["description"] = source.get("description")
        results.append(source)
    return results


def _iter_process_identifiers(finding: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for aliases in (
        ("pid", "process_id", "processId"),
        ("parent_pid", "parent_process_id", "parentProcessId"),
        ("process_guid", "processGuid"),
        ("parent_process_guid", "parentProcessGuid"),
        ("created_by_pid", "createdByPid"),
        ("event_uid", "eventUid"),
        ("process", "process_name", "processName"),
        ("parent_process", "parent_process_name", "parentProcessName"),
    ):
        value = _field_value(finding, *aliases)
        if value is not None:
            text = str(value).strip()
            if text:
                values.append(text.lower())
    return values


def _process_related(f1: dict[str, Any], f2: dict[str, Any]) -> list[str]:
    reasons: list[str] = []

    shared_identifiers = {
        "pid": ("pid", "process_id", "processId"),
        "parent_pid": ("parent_pid", "parent_process_id", "parentProcessId"),
        "process_guid": ("process_guid", "processGuid"),
        "parent_process_guid": ("parent_process_guid", "parentProcessGuid"),
        "event_uid": ("event_uid", "eventUid"),
        "task_name": ("task_name", "taskName"),
        "service_name": ("service_name", "serviceName"),
        "registry_path": ("registry_path", "registryPath"),
        "indicator": ("indicator",),
        "path": ("path",),
        "ip": ("ip", "ip_address"),
    }
    host1 = _normalize_host(f1.get("host"))
    host2 = _normalize_host(f2.get("host"))
    ts1 = _parse_timestamp(f1.get("timestamp"))
    ts2 = _parse_timestamp(f2.get("timestamp"))

    for key, aliases in shared_identifiers.items():
        v1 = _field_value(f1, *aliases)
        v2 = _field_value(f2, *aliases)
        if _has_non_empty_value(v1) and _has_non_empty_value(v2) and str(v1) == str(v2):
            if key in {"pid"}:
                if host1 and host2 and host1 == host2 and ts1 and ts2:
                    delta_minutes = abs((ts2 - ts1).total_seconds()) / 60.0
                    if delta_minutes <= DEFAULT_CORRELATION_WINDOW_MINUTES:
                        reasons.append("shared_pid")
            elif key in {"process_guid", "parent_process_guid"}:
                reasons.append("shared_process_guid")
            elif key in {"task_name"}:
                if host1 and host2 and host1 == host2 and ts1 and ts2:
                    delta_minutes = abs((ts2 - ts1).total_seconds()) / 60.0
                    if delta_minutes <= DEFAULT_CORRELATION_WINDOW_MINUTES:
                        reasons.append("shared_task")
            elif key in {"service_name"}:
                if host1 and host2 and host1 == host2 and ts1 and ts2:
                    delta_minutes = abs((ts2 - ts1).total_seconds()) / 60.0
                    if delta_minutes <= DEFAULT_CORRELATION_WINDOW_MINUTES:
                        reasons.append("shared_service")
            elif key in {"registry_path"}:
                if host1 and host2 and host1 == host2 and ts1 and ts2:
                    delta_minutes = abs((ts2 - ts1).total_seconds()) / 60.0
                    if delta_minutes <= DEFAULT_CORRELATION_WINDOW_MINUTES:
                        reasons.append("shared_registry_path")
            elif key in {"indicator", "path", "ip"}:
                if host1 and host2 and host1 == host2 and ts1 and ts2:
                    delta_minutes = abs((ts2 - ts1).total_seconds()) / 60.0
                    if delta_minutes <= DEFAULT_CORRELATION_WINDOW_MINUTES:
                        reasons.append("shared_indicator")
            elif key in {"event_uid"}:
                reasons.append("shared_process")

    proc1 = {
        "pid": _field_value(f1, "pid", "process_id", "processId"),
        "ppid": _field_value(f1, "parent_pid", "parent_process_id", "parentProcessId"),
        "process_guid": _field_value(f1, "process_guid", "processGuid"),
        "parent_process_guid": _field_value(f1, "parent_process_guid", "parentProcessGuid"),
    }
    proc2 = {
        "pid": _field_value(f2, "pid", "process_id", "processId"),
        "ppid": _field_value(f2, "parent_pid", "parent_process_id", "parentProcessId"),
        "process_guid": _field_value(f2, "process_guid", "processGuid"),
        "parent_process_guid": _field_value(f2, "parent_process_guid", "parentProcessGuid"),
    }
    if (host1 and host2 and host1 == host2 and ts1 and ts2 and _has_non_empty_value(proc1["pid"]) and _has_non_empty_value(proc2["ppid"]) and str(proc1["pid"]) == str(proc2["ppid"])):
        delta_minutes = abs((ts2 - ts1).total_seconds()) / 60.0
        if delta_minutes <= DEFAULT_CORRELATION_WINDOW_MINUTES:
            reasons.append("parent_child_process")
    if (host1 and host2 and host1 == host2 and ts1 and ts2 and _has_non_empty_value(proc2["pid"]) and _has_non_empty_value(proc1["ppid"]) and str(proc2["pid"]) == str(proc1["ppid"])):
        delta_minutes = abs((ts2 - ts1).total_seconds()) / 60.0
        if delta_minutes <= DEFAULT_CORRELATION_WINDOW_MINUTES:
            reasons.append("parent_child_process")
    if _has_non_empty_value(proc1["process_guid"]) and _has_non_empty_value(proc2["process_guid"]) and str(proc1["process_guid"]) == str(proc2["process_guid"]):
        reasons.append("shared_process_guid")
    if _has_non_empty_value(proc1["parent_process_guid"]) and _has_non_empty_value(proc2["parent_process_guid"]) and str(proc1["parent_process_guid"]) == str(proc2["parent_process_guid"]):
        reasons.append("shared_process_guid")

    names1 = {
        _normalize_process_name(_field_value(f1, "process", "process_name", "processName")),
        _normalize_process_name(_field_value(f1, "parent_process", "parent_process_name", "parentProcessName")),
    }
    names2 = {
        _normalize_process_name(_field_value(f2, "process", "process_name", "processName")),
        _normalize_process_name(_field_value(f2, "parent_process", "parent_process_name", "parentProcessName")),
    }
    names1 = {name for name in names1 if name}
    names2 = {name for name in names2 if name}
    if names1 & names2:
        ts1 = _parse_timestamp(f1.get("timestamp"))
        ts2 = _parse_timestamp(f2.get("timestamp"))
        if ts1 and ts2:
            delta = abs((ts2 - ts1).total_seconds()) / 60.0
            if delta <= DEFAULT_CORRELATION_WINDOW_MINUTES:
                host1 = _normalize_host(f1.get("host"))
                host2 = _normalize_host(f2.get("host"))
                user1 = _normalize_user(f1.get("user"))
                user2 = _normalize_user(f2.get("user"))
                if (host1 and host2 and host1 == host2) and (not user1 or not user2 or user1 == user2):
                    reasons.append("shared_process")

    return sorted(set(reasons), key=lambda item: item)


def _normalize_event_record(event: Any) -> dict[str, Any]:
    if not isinstance(event, dict):
        return {}
    event_copy = copy.deepcopy(event)
    evidence = event_copy.get("evidence") if isinstance(event_copy.get("evidence"), dict) else {}
    if not isinstance(evidence, dict):
        evidence = {}
    event_copy["evidence"] = _json_safe(evidence)
    return event_copy


def _event_lookup(events: Any) -> dict[str, list[dict[str, Any]]]:
    if not events:
        return {}
    lookup: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if isinstance(events, dict):
        iterable: Iterable[Any] = [events]
    else:
        iterable = events
    for record in iterable:
        record = _normalize_event_record(record)
        if not record:
            continue
        host = _normalize_host(record.get("host"))
        user = _normalize_user(record.get("user"))
        ts = _parse_timestamp(record.get("timestamp"))
        key_fields = [
            ("pid", "process_id", "processId"),
            ("parent_pid", "parent_process_id", "parentProcessId"),
            ("process_guid", "processGuid"),
            ("parent_process_guid", "parentProcessGuid"),
        ]
        for aliases in key_fields:
            value = _field_value(record, *aliases)
            if value is not None:
                lookup[f"{aliases[0]}:{str(value)}"].append(record)
        if host:
            lookup[f"host:{host}"].append(record)
        if user:
            lookup[f"user:{user}"].append(record)
        if ts is not None:
            lookup[f"time:{ts.isoformat()}"].append(record)
    return lookup


def _pair_reasons_for_findings(
    f1: dict[str, Any],
    f2: dict[str, Any],
    event_lookup: Optional[dict[str, list[dict[str, Any]]]] = None,
) -> list[str]:
    """Compute correlation reasons for a single finding pair.

    The expensive event-index scan is intentionally passed in from a precomputed
    lookup so this logic can be reused without rebuilding the full index for
    every pair during chain construction.
    """
    reasons: list[str] = []
    host1 = _normalize_host(f1.get("host"))
    host2 = _normalize_host(f2.get("host"))
    user1 = _normalize_user(f1.get("user"))
    user2 = _normalize_user(f2.get("user"))
    ts1 = _parse_timestamp(f1.get("timestamp"))
    ts2 = _parse_timestamp(f2.get("timestamp"))

    if host1 and host2 and host1 == host2:
        reasons.append("same_host")

    if user1 and user2 and user1 == user2:
        reasons.append("same_user")

    if ts1 and ts2:
        delta_minutes = abs((ts2 - ts1).total_seconds()) / 60.0
        if delta_minutes <= DEFAULT_CORRELATION_WINDOW_MINUTES:
            reasons.append("within_30_minutes")
        if delta_minutes <= DEFAULT_WEAK_HOST_WINDOW_MINUTES and host1 and host2 and host1 == host2 and not (user1 and user2 and user1 == user2):
            reasons.append("within_10_minutes")

    reasons.extend(_process_related(f1, f2))

    if event_lookup is not None:
        strong_event_match = False
        for aliases in (
            ("pid", "process_id", "processId"),
            ("parent_pid", "parent_process_id", "parentProcessId"),
            ("process_guid", "processGuid"),
            ("parent_process_guid", "parentProcessGuid"),
        ):
            val1 = _field_value(f1, *aliases)
            val2 = _field_value(f2, *aliases)
            if val1 is not None and val2 is not None and str(val1) == str(val2):
                strong_event_match = True
                break
        if strong_event_match:
            if "shared_process" not in reasons and "shared_process_guid" not in reasons and "parent_child_process" not in reasons:
                reasons.append("shared_process")

        h1 = host1 or ""
        h2 = host2 or ""
        if h1 and h2 and h1 == h2 and ts1 and ts2:
            delta = abs((ts2 - ts1).total_seconds()) / 60.0
            if delta <= DEFAULT_CORRELATION_WINDOW_MINUTES and (not user1 or not user2 or user1 == user2):
                reasons.append("within_30_minutes")

    reasons = sorted(set(reasons), key=lambda item: item)
    return reasons


def _pair_reasons(f1: dict[str, Any], f2: dict[str, Any], events: Any = None) -> list[str]:
    event_lookup = _event_lookup(events) if events else None
    return _pair_reasons_for_findings(f1, f2, event_lookup)


def _sorted_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    def sort_key(item: dict[str, Any]) -> tuple[Any, ...]:
        ts = item.get("_timestamp")
        if ts is not None:
            value = ts
        else:
            value = datetime.max.replace(tzinfo=timezone.utc)
        return (
            value,
            item.get("_host") or "",
            item.get("_user") or "",
            item.get("_stage") or "",
            item.get("_identity") or "",
            item.get("_source", {}).get("finding_type") or "",
        )

    return sorted(findings, key=sort_key)


class EventCorrelator:
    """Group WinHunt findings into chronological, evidence-backed investigation chains."""

    def __init__(self, findings: Any = None, events: Any = None):
        self.findings = self._prepare_findings(findings)
        self.events = events

    def _prepare_findings(self, findings: Any) -> list[dict[str, Any]]:
        prepared: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in _coerce_findings(findings):
            host = _normalize_host(item.get("host"))
            user = _normalize_user(item.get("user"))
            ts = _parse_timestamp(item.get("timestamp"))
            finding_type = str(item.get("finding_type") or "unknown")
            source = copy.deepcopy(item)
            source["evidence"] = _json_safe(source.get("evidence") or {})
            identity = _stable_finding_id(source)
            if identity in seen:
                continue
            seen.add(identity)
            prepared.append(
                {
                    "_source": source,
                    "_identity": identity,
                    "_timestamp": ts,
                    "_host": host,
                    "_user": user,
                    "_stage": _derive_stage(finding_type),
                    "_finding_type": finding_type,
                }
            )
        return prepared

    def correlate(self) -> list[dict]:
        return self._build_chains()

    def build_attack_chains(self) -> list[dict]:
        return self._build_chains()

    def _build_chains(self) -> list[dict]:
        findings = _sorted_findings(self.findings)
        if not findings:
            return []

        event_lookup = _event_lookup(self.events) if self.events else None
        pair_reason_cache: dict[tuple[int, int], list[str]] = {}

        parent = list(range(len(findings)))

        def find(index: int) -> int:
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        def union(left: int, right: int) -> None:
            root_left = find(left)
            root_right = find(right)
            if root_left != root_right:
                parent[root_right] = root_left

        for i in range(len(findings)):
            for j in range(i + 1, len(findings)):
                cache_key = (i, j)
                if cache_key not in pair_reason_cache:
                    pair_reason_cache[cache_key] = _pair_reasons_for_findings(
                        findings[i]["_source"],
                        findings[j]["_source"],
                        event_lookup,
                    )
                reasons = pair_reason_cache[cache_key]
                if not reasons:
                    continue
                host_a = _normalize_host(findings[i]["_source"].get("host"))
                host_b = _normalize_host(findings[j]["_source"].get("host"))
                user_a = _normalize_user(findings[i]["_source"].get("user"))
                user_b = _normalize_user(findings[j]["_source"].get("user"))
                ts_a = _parse_timestamp(findings[i]["_source"].get("timestamp"))
                ts_b = _parse_timestamp(findings[j]["_source"].get("timestamp"))
                strong = bool(reasons and (
                    "shared_process" in reasons
                    or "shared_pid" in reasons
                    or "shared_process_guid" in reasons
                    or "parent_child_process" in reasons
                    or "shared_task" in reasons
                    or "shared_service" in reasons
                    or "shared_registry_path" in reasons
                    or "shared_indicator" in reasons
                ))

                if strong:
                    union(i, j)
                    continue

                if host_a and host_b and host_a == host_b:
                    if user_a and user_b and user_a == user_b and ts_a and ts_b:
                        delta_min = abs((ts_b - ts_a).total_seconds()) / 60.0
                        if delta_min <= DEFAULT_CORRELATION_WINDOW_MINUTES:
                            union(i, j)
                            continue
                    if (not user_a or not user_b) and ts_a and ts_b:
                        delta_min = abs((ts_b - ts_a).total_seconds()) / 60.0
                        if delta_min <= DEFAULT_WEAK_HOST_WINDOW_MINUTES:
                            union(i, j)
                            continue

        groups: dict[int, list[int]] = defaultdict(list)
        for idx in range(len(findings)):
            groups[find(idx)].append(idx)

        chains: list[dict] = []
        for root in sorted(groups.keys(), key=lambda key: min(groups[key])):
            members = sorted(groups[root], key=lambda idx: (findings[idx]["_timestamp"] or datetime.max.replace(tzinfo=timezone.utc), findings[idx]["_identity"]))
            if len(members) == 1:
                # single findings are valid only when they have evidence-based relationship to nothing else
                # keep them as a chain because the API expects chains, not dangling singles.
                pass

            chain_members = [findings[idx] for idx in members]
            chain_findings = [copy.deepcopy(member["_source"]) for member in chain_members]
            chain_findings = [self._ensure_serializable(f) for f in chain_findings]
            host_names = sorted({item.get("host") for item in chain_findings if item.get("host") is not None})
            host = host_names[0] if host_names else None
            users = sorted({str(item.get("user")).lower() for item in chain_findings if item.get("user") not in (None, "")})
            timestamps = [member["_timestamp"] for member in chain_members if member["_timestamp"] is not None]
            start_time = min(timestamps).astimezone(timezone.utc).isoformat() if timestamps else ""
            end_time = max(timestamps).astimezone(timezone.utc).isoformat() if timestamps else ""
            duration_seconds = int((max(timestamps) - min(timestamps)).total_seconds()) if len(timestamps) >= 2 else 0
            stages = [member["_stage"] for member in chain_members]
            reason_pairs: list[dict[str, Any]] = []
            for left in range(len(chain_members)):
                for right in range(left + 1, len(chain_members)):
                    global_left = members[left]
                    global_right = members[right]
                    lower_idx, higher_idx = sorted((global_left, global_right))
                    pair_cache_key = (lower_idx, higher_idx)
                    if pair_cache_key not in pair_reason_cache:
                        pair_reason_cache[pair_cache_key] = _pair_reasons_for_findings(
                            chain_members[left]["_source"],
                            chain_members[right]["_source"],
                            event_lookup,
                        )
                    pair_reasons = pair_reason_cache[pair_cache_key]
                    if not pair_reasons:
                        continue
                    reason_pairs.append({
                        "from_index": left,
                        "to_index": right,
                        "reasons": pair_reasons,
                    })
            # Keep deterministic ordering for reasons.
            reason_pairs.sort(key=lambda item: (item["from_index"], item["to_index"], item["reasons"]))
            chain = {
                "chain_id": "",
                "start_time": start_time,
                "end_time": end_time,
                "duration_seconds": duration_seconds,
                "host": host,
                "users": users,
                "finding_count": len(chain_findings),
                "stages": stages,
                "findings": chain_findings,
                "correlation_reasons": reason_pairs,
            }
            chains.append(chain)

        chains.sort(
            key=lambda item: (
                item["start_time"] or "",
                item["host"] or "",
                item["users"],
                item["finding_count"],
                len(item["findings"]),
            )
        )

        for index, chain in enumerate(chains, start=1):
            chain["chain_id"] = f"CHAIN-{index:03d}"
        return chains

    @staticmethod
    def _ensure_serializable(value: Any) -> Any:
        json.dumps(value, default=_json_safe)
        return _json_safe(value)


def correlate_findings(findings: Any, events: Any = None) -> list[dict]:
    """Return correlated chains for a collection of findings."""
    return EventCorrelator(findings=findings, events=events).correlate()


def build_attack_chains(findings: Any, events: Any = None) -> list[dict]:
    """Build correlated attack chains from WinHunt findings."""
    return EventCorrelator(findings=findings, events=events).build_attack_chains()
