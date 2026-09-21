"""Detection rules for suspicious persistence activity."""


def detect_scheduled_task_creation(event):
    """Return a finding when a scheduled task creation event is observed."""
    if not isinstance(event, dict):
        return None

    if event.get("event_type") != "scheduled_task":
        return None

    evidence = {}
    for key in ("task_name", "action", "created_by_process", "created_by_pid", "user", "host"):
        if key in event:
            evidence[key] = event.get(key)

    return {
        "rule_id": "WINHUNT-004",
        "rule_name": "Scheduled Task Created",
        "severity": "medium",
        "timestamp": event.get("timestamp"),
        "event_id": event.get("event_id"),
        "event_type": event.get("event_type"),
        "pid": event.get("pid"),
        "process": event.get("process"),
        "reason": "A scheduled task was created, which may indicate persistence and warrants investigation.",
        "evidence": evidence,
    }
