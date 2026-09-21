"""Detection rules for suspicious process relationships."""

import ntpath


OFFICE_EXECUTABLES = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"}
POWERSHELL_EXECUTABLES = {"powershell.exe", "pwsh.exe"}


def _is_process_name(value, accepted_names):
    """Return True when the executable basename exactly matches an accepted name."""
    if not value:
        return False

    basename = ntpath.basename(str(value)).lower()
    return basename in {name.lower() for name in accepted_names}


def detect_office_to_powershell(event):
    """Return a finding when an Office process launches a PowerShell process."""
    if not isinstance(event, dict):
        return None

    if event.get("event_type") != "process":
        return None

    process = event.get("process")
    parent_process = event.get("parent_process")
    if not process or not parent_process:
        return None

    if not _is_process_name(process, POWERSHELL_EXECUTABLES):
        return None

    if not _is_process_name(parent_process, OFFICE_EXECUTABLES):
        return None

    return {
        "rule_id": "WINHUNT-002",
        "rule_name": "Office Application Spawned PowerShell",
        "severity": "high",
        "timestamp": event.get("timestamp"),
        "event_id": event.get("event_id"),
        "event_type": event.get("event_type"),
        "pid": event.get("pid"),
        "process": process,
        "reason": "Office application spawned a PowerShell process",
        "evidence": {
            "process": process,
            "parent_process": parent_process,
            "command_line": event.get("command_line"),
        },
    }
