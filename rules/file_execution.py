"""Detection rules for suspicious executable locations."""

import ntpath


def _is_windows_executable(value):
    """Return True when the basename represents a Windows executable."""
    if not value:
        return False

    basename = ntpath.basename(str(value).strip())
    return basename.lower().endswith(".exe")


def _suspicious_location(path_value):
    """Return the suspicious Windows user-writable location if present."""
    if not path_value:
        return None

    normalized = str(path_value).replace("/", "\\")
    parts = [part.lower() for part in ntpath.normpath(normalized).split("\\") if part]

    if "appdata" in parts:
        return "AppData"
    if "temp" in parts:
        return "Temp"
    return None


def detect_suspicious_executable_location(event):
    """Return a finding when an executable is launched from AppData or Temp."""
    if not isinstance(event, dict):
        return None

    if event.get("event_type") != "process":
        return None

    process = event.get("process")
    if not process or not str(process).strip():
        return None

    if not _is_windows_executable(process):
        return None

    location = _suspicious_location(process)
    if location is None:
        return None

    reason = f"Executable observed from a suspicious {location} location"

    return {
        "rule_id": "WINHUNT-003",
        "rule_name": "Suspicious Executable from User-Writable Location",
        "severity": "medium",
        "timestamp": event.get("timestamp"),
        "event_id": event.get("event_id"),
        "event_type": event.get("event_type"),
        "pid": event.get("pid"),
        "process": process,
        "reason": reason,
        "evidence": {
            "process": process,
            "command_line": event.get("command_line"),
            "location": location,
        },
    }
