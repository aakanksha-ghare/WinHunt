"""Detection rules for suspicious PowerShell activity."""

import shlex


def _has_encoded_command_argument(command_line):
    """Return True when a PowerShell command contains an encoded-command switch."""
    if not isinstance(command_line, str):
        return False

    try:
        parts = shlex.split(command_line, posix=False)
    except ValueError:
        parts = command_line.split()

    for argument in parts[1:]:
        normalized_argument = str(argument).strip().strip("'\"").lower()
        if normalized_argument in {"-enc", "-encodedcommand"}:
            return True

    return False


def detect_encoded_powershell(event):
    """Return a finding when a PowerShell process executes an encoded command."""
    if not isinstance(event, dict):
        return None

    if event.get("event_type") != "process":
        return None

    process = event.get("process")
    if not process:
        return None

    process_name = str(process).lower()
    if not (
        process_name.endswith("powershell.exe")
        or process_name.endswith("pwsh.exe")
    ):
        return None

    command_line = event.get("command_line")
    if not isinstance(command_line, str):
        return None

    if not _has_encoded_command_argument(command_line):
        return None

    return {
        "rule_id": "WINHUNT-001",
        "rule_name": "Encoded PowerShell",
        "severity": "high",
        "timestamp": event.get("timestamp"),
        "event_id": event.get("event_id"),
        "event_type": event.get("event_type"),
        "pid": event.get("pid"),
        "process": process,
        "reason": "PowerShell command contains an encoded-command indicator",
        "evidence": {
            "command_line": command_line,
        },
    }
