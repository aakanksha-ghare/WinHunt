"""Conservative MITRE ATT&CK enrichment for WinHunt findings.

Purpose
-------
This module enriches existing WinHunt findings with ATT&CK technique metadata
without creating detections, recalculating risk, or altering the original
finding objects. The mapper is intentionally conservative: it only adds MITRE
information when the finding type or already-present evidence clearly matches a
known ATT&CK-linked behavior.

The ATT&CK mapping is contextual evidence, not proof of compromise. A mapped
technique reflects a suspicious behavior consistent with the ATT&CK taxonomy;
it does not assert that malicious execution, credential theft, or compromise has
been confirmed.

Public API
----------
- map_finding(finding): map a single finding to MITRE ATT&CK entries.
- map_findings(findings): map a list of findings while preserving order.
- map_chain(chain): map each finding in a correlated chain and aggregate the
  chain-level MITRE entries without altering the chain's core correlation fields.

Supported mappings are limited to explicit WinHunt findings such as encoded
PowerShell, scheduled task creation, Run key persistence, service installation,
new-account creation, failed-login bursts, WMI event-subscription persistence,
and specific process-injection evidence.
"""

from __future__ import annotations

import copy
import re
from typing import Any, Iterable

__all__ = [
    "map_finding",
    "map_findings",
    "map_chain",
]

_TECHNIQUE_DATA = {
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactics": ("Execution",),
    },
    "T1053.005": {
        "name": "Scheduled Task/Job: Scheduled Task",
        "tactics": ("Execution", "Persistence", "Privilege Escalation"),
    },
    "T1547.001": {
        "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
        "tactics": ("Persistence", "Privilege Escalation"),
    },
    "T1569.002": {
        "name": "System Services: Service Execution",
        "tactics": ("Execution",),
    },
    "T1136.001": {
        "name": "Create Account: Local Account",
        "tactics": ("Persistence",),
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactics": ("Credential Access",),
    },
    "T1055": {
        "name": "Process Injection",
        "tactics": ("Stealth", "Privilege Escalation"),
    },
    "T1546.003": {
        "name": "Event Triggered Execution: Windows Management Instrumentation Event Subscription",
        "tactics": ("Privilege Escalation", "Persistence"),
    },
}

_TYPE_ALIASES: dict[str, str] = {
    "encoded_powershell": "T1059.001",
    "encoded_power_shell": "T1059.001",
    "office_to_powershell": "T1059.001",
    "office_to_power_shell": "T1059.001",
    "office_application_spawned_powershell": "T1059.001",
    "office_application_spawned_power_shell": "T1059.001",
    "scheduled_task_creation": "T1053.005",
    "scheduled_task_created": "T1053.005",
    "scheduled_task_persistence": "T1053.005",
    "registry_run_key_persistence": "T1547.001",
    "registry_run_key": "T1547.001",
    "startup_persistence": "T1547.001",
    "service_installation": "T1569.002",
    "new_account": "T1136.001",
    "new_account_created": "T1136.001",
    "failed_login_burst": "T1110.001",
    "process_injection": "T1055",
    "process_injection_related": "T1055",
    "remote_thread_injection": "T1055",
    "wmi_event_subscription": "T1546.003",
    "wmi_event_subscription_persistence": "T1546.003",
    "wmi_persistence": "T1546.003",
}


def _normalize_key(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip().lower()
    text = text.replace("-", "_")
    text = text.replace(" ", "_")
    text = re.sub(r"[^a-z0-9_]+", "_", text)
    text = re.sub(r"_+", "_", text).strip("_")
    return text


def _is_non_empty(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return True


def _safe_top_level_and_evidence(record: dict[str, Any], *aliases: str) -> Any:
    if not isinstance(record, dict):
        return None
    for alias in aliases:
        value = record.get(alias)
        if _is_non_empty(value):
            return value
    evidence = record.get("evidence")
    if isinstance(evidence, dict):
        for alias in aliases:
            value = evidence.get(alias)
            if _is_non_empty(value):
                return value
        for key, value in evidence.items():
            if _normalize_key(key) in {_normalize_key(alias) for alias in aliases} and _is_non_empty(value):
                return value
    return None


def _value_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items: list[Any] = list(value)
    else:
        items = [value]
    results: list[str] = []
    for item in items:
        if item is None:
            continue
        text = str(item).strip()
        if text:
            results.append(text)
    return results


def _extract_event_ids(finding: dict[str, Any]) -> set[int]:
    ids: set[int] = set()
    for key in ("event_id", "eventId", "EventID"):
        value = _safe_top_level_and_evidence(finding, key)
        if value is not None:
            try:
                ids.add(int(value))
            except (TypeError, ValueError):
                pass
    for key in ("event_ids", "eventIds", "EventIDs"):
        value = _safe_top_level_and_evidence(finding, key)
        if isinstance(value, (list, tuple, set)):
            for item in value:
                try:
                    ids.add(int(item))
                except (TypeError, ValueError):
                    pass
        elif value is not None:
            try:
                ids.add(int(value))
            except (TypeError, ValueError):
                pass
    return ids


def _extract_lookup_texts(finding: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    for key in (
        "finding_type",
        "rule_name",
        "rule_id",
        "process",
        "parent_process",
        "command_line",
        "registry_path",
        "path",
        "task_name",
        "service_name",
        "new_account",
        "account",
        "target_user",
        "source_ip",
        "ip",
        "filter_name",
        "consumer_name",
        "subscription_name",
        "event_type",
        "event_type_name",
    ):
        value = _safe_top_level_and_evidence(finding, key)
        texts.extend(_value_list(value))
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    for key, value in evidence.items():
        key_text = _normalize_key(key)
        if key_text in {
            "process",
            "parent_process",
            "command_line",
            "registry_path",
            "path",
            "task_name",
            "service_name",
            "new_account",
            "account",
            "target_user",
            "source_ip",
            "ip",
            "filter_name",
            "consumer_name",
            "subscription_name",
            "event_type",
            "event_type_name",
        }:
            texts.extend(_value_list(value))
    return texts


def _has_encoded_powershell(finding: dict[str, Any]) -> bool:
    process = _safe_top_level_and_evidence(finding, "process", "process_name", "processName")
    if process is not None:
        proc_name = str(process).lower().strip()
        if proc_name.endswith("powershell.exe") or proc_name.endswith("pwsh.exe"):
            pass
        else:
            return False
    else:
        proc_name = ""
    command_line = _safe_top_level_and_evidence(finding, "command_line", "commandLine")
    if command_line is None:
        command_line = ""
    text = str(command_line).strip()
    if "-enc" in text.lower() or "-encodedcommand" in text.lower():
        return True
    return bool(proc_name) and "-enc" in str(finding.get("command_line") or "").lower()


def _has_office_to_powershell(finding: dict[str, Any]) -> bool:
    process = _safe_top_level_and_evidence(finding, "process", "process_name", "processName")
    parent_process = _safe_top_level_and_evidence(finding, "parent_process", "parentProcess")
    if process is None or parent_process is None:
        return False
    proc = str(process).lower().strip()
    parent = str(parent_process).lower().strip()
    office_names = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
    powershell_names = {"powershell.exe", "pwsh.exe"}
    return proc in powershell_names and parent in office_names


def _has_explicit_process_injection_type(finding: dict[str, Any]) -> bool:
    for candidate in _raw_mapping_candidates(finding):
        if candidate in {
            "process_injection",
            "process_injection_related",
            "process_injection_detection",
            "remote_thread_injection",
            "remote_thread_injection_detection",
        }:
            return True
        if "process_injection" in candidate or "remote_thread_injection" in candidate:
            return True
    return False


def _is_process_injection_finding(finding: dict[str, Any]) -> bool:
    if _has_explicit_process_injection_type(finding):
        return True

    event_ids = _extract_event_ids(finding)
    if {8, 10}.issubset(event_ids):
        return True

    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    has_process_access = False
    has_create_remote_thread = False

    for key, value in evidence.items():
        normalized_key = _normalize_key(key)
        if normalized_key in {"process_access", "process_access_event"}:
            has_process_access = True
        if normalized_key in {"create_remote_thread", "createremotethread", "remote_thread", "remotethread"}:
            has_create_remote_thread = True

        if isinstance(value, str):
            lower = value.lower()
            if "process injection" in lower or "process_injection" in lower or "injection detected" in lower:
                return True
            if "process access" in lower:
                has_process_access = True
            if "create remote thread" in lower or "create_remotethread" in lower or "remote thread" in lower:
                has_create_remote_thread = True

    return has_process_access and has_create_remote_thread


def _is_wmi_event_subscription_finding(finding: dict[str, Any]) -> bool:
    keys = [_normalize_key(value) for value in _extract_lookup_texts(finding)]
    type_text = " ".join(keys)
    if any(token in type_text for token in ("wmi_event_subscription", "wmi_subscription", "wmisubscription", "event_subscription_persistence")):
        return True
    evidence = finding.get("evidence") if isinstance(finding.get("evidence"), dict) else {}
    explicit_keys = {"subscription_name", "subscription", "filter_name", "filter", "consumer_name", "consumer", "query", "event_filter", "event_consumer"}
    key_names = {_normalize_key(key) for key in evidence.keys()}
    if key_names & explicit_keys:
        value_text = " ".join(str(v) for v in evidence.values() if isinstance(v, (str, int, float, bool)))
        lower = value_text.lower()
        if "wmi" in lower or "subscription" in lower or "event filter" in lower or "event consumer" in lower:
            return True
    return False


def _raw_mapping_candidates(finding: dict[str, Any]) -> list[str]:
    candidates: list[str] = []
    for key in ("finding_type", "rule_name", "rule_id", "type"):
        value = _safe_top_level_and_evidence(finding, key)
        if value is not None:
            candidates.append(_normalize_key(value))
    if not candidates:
        candidates.extend(_normalize_key(item) for item in _extract_lookup_texts(finding))
    return [candidate for candidate in candidates if candidate]


def _build_technique_entries(technique_id: str) -> list[dict[str, Any]]:
    info = _TECHNIQUE_DATA[technique_id]
    entries: list[dict[str, Any]] = []
    for tactic in info["tactics"]:
        entries.append(
            {
                "technique_id": technique_id,
                "technique_name": info["name"],
                "tactic": tactic,
                "source": "WinHunt detection mapping",
            }
        )
    return entries


def _merge_mitre(existing: Any, incoming: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    for item in existing if isinstance(existing, list) else []:
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("technique_id") or "").strip()
        tactic = str(item.get("tactic") or "").strip()
        technique_name = str(item.get("technique_name") or "").strip()
        if not technique_id:
            continue
        key = (technique_id, tactic, technique_name)
        if key in seen:
            continue
        seen.add(key)
        merged.append({
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "source": str(item.get("source") or "WinHunt detection mapping"),
        })

    for item in incoming:
        if not isinstance(item, dict):
            continue
        technique_id = str(item.get("technique_id") or "").strip()
        tactic = str(item.get("tactic") or "").strip()
        technique_name = str(item.get("technique_name") or "").strip()
        if not technique_id:
            continue
        key = (technique_id, tactic, technique_name)
        if key in seen:
            continue
        seen.add(key)
        merged.append({
            "technique_id": technique_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "source": str(item.get("source") or "WinHunt detection mapping"),
        })

    merged.sort(key=lambda item: (item.get("technique_id") or "", item.get("tactic") or "", item.get("technique_name") or ""))
    return merged


def _map_finding_type(finding: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = _raw_mapping_candidates(finding)
    mapped: list[dict[str, Any]] = []
    for candidate in candidates:
        technique_id = _TYPE_ALIASES.get(candidate)
        if technique_id is None:
            continue
        mapped.extend(_build_technique_entries(technique_id))
    if mapped:
        return _merge_mitre([], mapped)
    return []


def _detect_evidence_based_mappings(finding: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    if _has_encoded_powershell(finding):
        entries.extend(_build_technique_entries("T1059.001"))
    if _has_office_to_powershell(finding):
        entries.extend(_build_technique_entries("T1059.001"))
    if _is_process_injection_finding(finding):
        entries.extend(_build_technique_entries("T1055"))
    if _is_wmi_event_subscription_finding(finding):
        entries.extend(_build_technique_entries("T1546.003"))
    if entries:
        return _merge_mitre([], entries)
    return []


def _map_mitre_entries(finding: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    entries.extend(_map_finding_type(finding))
    entries.extend(_detect_evidence_based_mappings(finding))
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in entries:
        key = (str(entry.get("technique_id") or ""), str(entry.get("tactic") or ""), str(entry.get("technique_name") or ""))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entry)
    deduped.sort(key=lambda item: (item.get("technique_id") or "", item.get("tactic") or "", item.get("technique_name") or ""))
    return deduped


def map_finding(finding: Any) -> dict[str, Any]:
    """Map a single WinHunt finding to ATT&CK technique metadata.

    The function returns a deep copy of the original finding. Original caller-owned
    dictionaries are never mutated.
    """
    if finding is None:
        return {"mitre": []}
    if not isinstance(finding, dict):
        return {"mitre": []}

    result = copy.deepcopy(finding)
    mapped = _map_mitre_entries(result)
    existing = result.get("mitre")
    if existing is None:
        result["mitre"] = mapped
    else:
        result["mitre"] = _merge_mitre(existing, mapped)
    return result


def map_findings(findings: Any) -> list[dict[str, Any]]:
    """Map a sequence of findings while preserving the original order."""
    if findings is None:
        return []
    if isinstance(findings, dict):
        return [map_finding(findings)]
    if not isinstance(findings, Iterable):
        return []
    return [map_finding(item) for item in findings]


def map_chain(chain: Any) -> dict[str, Any]:
    """Map findings inside a correlated chain without disturbing the chain's core fields."""
    if chain is None:
        return {"mitre": []}
    if not isinstance(chain, dict):
        return {"mitre": []}

    result = copy.deepcopy(chain)
    findings = result.get("findings")
    if isinstance(findings, list):
        result["findings"] = [map_finding(item) for item in findings]

    aggregate: list[dict[str, Any]] = []
    for item in result.get("findings", []):
        if isinstance(item, dict):
            aggregate.extend(item.get("mitre", []))

    chain_existing = result.get("mitre")
    result["mitre"] = _merge_mitre(chain_existing, aggregate)
    return result
