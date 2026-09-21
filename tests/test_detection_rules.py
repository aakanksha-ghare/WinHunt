from rules.file_execution import detect_suspicious_executable_location
from rules.persistence import detect_scheduled_task_creation
from rules.powershell import detect_encoded_powershell
from rules.process import detect_office_to_powershell


def test_detect_encoded_powershell_positive_encoded_command():
    event = {
        "event_type": "process",
        "event_id": 1,
        "timestamp": "2026-09-15T10:00:00",
        "pid": 2420,
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc AAAABBBB",
    }

    finding = detect_encoded_powershell(event)

    assert finding is not None
    assert finding["rule_id"] == "WINHUNT-001"
    assert finding["severity"] == "high"
    assert finding["evidence"]["command_line"] == event["command_line"]


def test_detect_encoded_powershell_positive_encodedcommand_indicator():
    event = {
        "event_type": "process",
        "event_id": 2,
        "timestamp": "2026-09-15T10:01:00",
        "pid": 2421,
        "process": "PowerShell.exe",
        "command_line": "PowerShell.exe -EncodedCommand AAAABBBB",
    }

    finding = detect_encoded_powershell(event)

    assert finding is not None
    assert finding["rule_id"] == "WINHUNT-001"


def test_detect_encoded_powershell_case_insensitive_match():
    event = {
        "event_type": "process",
        "event_id": 3,
        "timestamp": "2026-09-15T10:02:00",
        "pid": 2422,
        "process": "POWERSHELL.EXE",
        "command_line": "POWERSHELL.EXE -ENC AAAABBBB",
    }

    finding = detect_encoded_powershell(event)

    assert finding is not None


def test_detect_encoded_powershell_positive_full_path_case_insensitive():
    event = {
        "event_type": "process",
        "event_id": 8,
        "timestamp": "2026-09-15T10:07:00",
        "pid": 2427,
        "process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -enc AAAABBBB",
    }

    finding = detect_encoded_powershell(event)

    assert finding is not None
    assert finding["process"] == event["process"]


def test_detect_encoded_powershell_negative_substring_false_positive():
    event = {
        "event_type": "process",
        "event_id": 9,
        "timestamp": "2026-09-15T10:08:00",
        "pid": 2428,
        "process": "powershell.exe",
        "command_line": "powershell.exe -encoding UTF8",
    }

    assert detect_encoded_powershell(event) is None


def test_detect_encoded_powershell_negative_textual_enc_reference():
    event = {
        "event_type": "process",
        "event_id": 10,
        "timestamp": "2026-09-15T10:09:00",
        "pid": 2429,
        "process": "powershell.exe",
        "command_line": "powershell.exe -Command \"Write-Host '-enc'\"",
    }

    assert detect_encoded_powershell(event) is None


def test_detect_encoded_powershell_negative_normal_powershell_command():
    event = {
        "event_type": "process",
        "event_id": 4,
        "timestamp": "2026-09-15T10:03:00",
        "pid": 2423,
        "process": "powershell.exe",
        "command_line": "powershell.exe -Command Get-Process",
    }

    assert detect_encoded_powershell(event) is None


def test_detect_encoded_powershell_negative_non_powershell_process_with_enc_text():
    event = {
        "event_type": "process",
        "event_id": 5,
        "timestamp": "2026-09-15T10:04:00",
        "pid": 2424,
        "process": "cmd.exe",
        "command_line": "cmd.exe /c echo \"-enc\"",
    }

    assert detect_encoded_powershell(event) is None


def test_detect_encoded_powershell_negative_non_process_event():
    event = {
        "event_type": "network",
        "process": "powershell.exe",
        "command_line": "powershell.exe -enc AAAA",
    }

    assert detect_encoded_powershell(event) is None


def test_detect_encoded_powershell_negative_missing_command_line():
    event = {
        "event_type": "process",
        "event_id": 6,
        "timestamp": "2026-09-15T10:05:00",
        "pid": 2425,
        "process": "pwsh.exe",
    }

    assert detect_encoded_powershell(event) is None


def test_detect_encoded_powershell_negative_missing_process_name():
    event = {
        "event_type": "process",
        "event_id": 7,
        "timestamp": "2026-09-15T10:06:00",
        "pid": 2426,
        "command_line": "powershell.exe -enc AAAA",
    }

    assert detect_encoded_powershell(event) is None


def test_detect_office_to_powershell_positive_word_to_powershell():
    event = {
        "event_type": "process",
        "event_id": 1,
        "timestamp": "2026-09-15T10:00:00",
        "pid": 2420,
        "process": "powershell.exe",
        "parent_pid": 2404,
        "parent_process": "winword.exe",
        "command_line": "powershell.exe -Command Get-Process",
    }

    finding = detect_office_to_powershell(event)

    assert finding is not None
    assert finding["rule_id"] == "WINHUNT-002"
    assert finding["severity"] == "high"
    assert finding["process"] == "powershell.exe"
    assert finding["evidence"]["parent_process"] == "winword.exe"


def test_detect_office_to_powershell_positive_excel_to_powershell():
    event = {
        "event_type": "process",
        "event_id": 2,
        "timestamp": "2026-09-15T10:01:00",
        "pid": 2421,
        "process": "powershell.exe",
        "parent_process": "excel.exe",
        "command_line": "powershell.exe -Command Get-Process",
    }

    assert detect_office_to_powershell(event) is not None


def test_detect_office_to_powershell_positive_powerpoint_to_powershell():
    event = {
        "event_type": "process",
        "event_id": 3,
        "timestamp": "2026-09-15T10:02:00",
        "pid": 2422,
        "process": "powershell.exe",
        "parent_process": "powerpnt.exe",
        "command_line": "powershell.exe -Command Get-Process",
    }

    assert detect_office_to_powershell(event) is not None


def test_detect_office_to_powershell_positive_outlook_to_powershell():
    event = {
        "event_type": "process",
        "event_id": 4,
        "timestamp": "2026-09-15T10:03:00",
        "pid": 2423,
        "process": "powershell.exe",
        "parent_process": "outlook.exe",
        "command_line": "powershell.exe -Command Get-Process",
    }

    assert detect_office_to_powershell(event) is not None


def test_detect_office_to_powershell_positive_pwsh_child():
    event = {
        "event_type": "process",
        "event_id": 5,
        "timestamp": "2026-09-15T10:04:00",
        "pid": 2424,
        "process": "pwsh.exe",
        "parent_process": "winword.exe",
        "command_line": "pwsh.exe -NoProfile",
    }

    assert detect_office_to_powershell(event) is not None


def test_detect_office_to_powershell_positive_case_insensitive():
    event = {
        "event_type": "process",
        "event_id": 6,
        "timestamp": "2026-09-15T10:05:00",
        "pid": 2425,
        "process": "POWERSHELL.EXE",
        "parent_process": "WINWORD.EXE",
        "command_line": "POWERSHELL.EXE -Command Get-Process",
    }

    assert detect_office_to_powershell(event) is not None


def test_detect_office_to_powershell_positive_full_paths():
    event = {
        "event_type": "process",
        "event_id": 7,
        "timestamp": "2026-09-15T10:06:00",
        "pid": 2426,
        "process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "parent_process": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
        "command_line": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Command Get-Process",
    }

    assert detect_office_to_powershell(event) is not None


def test_detect_office_to_powershell_negative_explorer_to_powershell():
    event = {
        "event_type": "process",
        "event_id": 8,
        "timestamp": "2026-09-15T10:07:00",
        "pid": 2427,
        "process": "powershell.exe",
        "parent_process": "explorer.exe",
        "command_line": "powershell.exe -Command Get-Process",
    }

    assert detect_office_to_powershell(event) is None


def test_detect_office_to_powershell_negative_fakepowershell_child():
    event = {
        "event_type": "process",
        "event_id": 14,
        "timestamp": "2026-09-15T10:13:00",
        "pid": 2433,
        "process": "fakepowershell.exe",
        "parent_process": "winword.exe",
        "command_line": "fakepowershell.exe",
    }

    assert detect_office_to_powershell(event) is None


def test_detect_office_to_powershell_negative_fakepwsh_child():
    event = {
        "event_type": "process",
        "event_id": 15,
        "timestamp": "2026-09-15T10:14:00",
        "pid": 2434,
        "process": "fakepwsh.exe",
        "parent_process": "winword.exe",
        "command_line": "fakepwsh.exe",
    }

    assert detect_office_to_powershell(event) is None


def test_detect_office_to_powershell_negative_fakewinword_parent():
    event = {
        "event_type": "process",
        "event_id": 16,
        "timestamp": "2026-09-15T10:15:00",
        "pid": 2435,
        "process": "powershell.exe",
        "parent_process": "fakewinword.exe",
        "command_line": "powershell.exe -Command Get-Process",
    }

    assert detect_office_to_powershell(event) is None


def test_detect_office_to_powershell_negative_cmd_to_powershell():
    event = {
        "event_type": "process",
        "event_id": 9,
        "timestamp": "2026-09-15T10:08:00",
        "pid": 2428,
        "process": "powershell.exe",
        "parent_process": "cmd.exe",
        "command_line": "powershell.exe -Command Get-Process",
    }

    assert detect_office_to_powershell(event) is None


def test_detect_office_to_powershell_negative_word_to_notepad():
    event = {
        "event_type": "process",
        "event_id": 10,
        "timestamp": "2026-09-15T10:09:00",
        "pid": 2429,
        "process": "notepad.exe",
        "parent_process": "winword.exe",
        "command_line": "notepad.exe",
    }

    assert detect_office_to_powershell(event) is None


def test_detect_office_to_powershell_negative_excel_to_cmd():
    event = {
        "event_type": "process",
        "event_id": 11,
        "timestamp": "2026-09-15T10:10:00",
        "pid": 2430,
        "process": "cmd.exe",
        "parent_process": "excel.exe",
        "command_line": "cmd.exe /c whoami",
    }

    assert detect_office_to_powershell(event) is None


def test_detect_office_to_powershell_negative_non_process_event():
    event = {
        "event_type": "network",
        "process": "powershell.exe",
        "parent_process": "winword.exe",
        "command_line": "powershell.exe -Command whoami",
    }

    assert detect_office_to_powershell(event) is None


def test_detect_office_to_powershell_negative_missing_parent_process():
    event = {
        "event_type": "process",
        "event_id": 12,
        "timestamp": "2026-09-15T10:11:00",
        "pid": 2431,
        "process": "powershell.exe",
        "command_line": "powershell.exe -Command whoami",
    }

    assert detect_office_to_powershell(event) is None


def test_detect_office_to_powershell_missing_command_line_still_detects():
    event = {
        "event_type": "process",
        "event_id": 13,
        "timestamp": "2026-09-15T10:12:00",
        "pid": 2432,
        "process": "powershell.exe",
        "parent_process": "outlook.exe",
    }

    finding = detect_office_to_powershell(event)

    assert finding is not None
    assert finding["evidence"]["command_line"] is None


def test_detect_scheduled_task_creation_positive_actual_normalized_event():
    event = {
        "event_type": "scheduled_task",
        "event_id": 4698,
        "timestamp": "2026-09-15T09:00:00.408Z",
        "task_name": "GoogleUpdateTaskMachineCore",
        "action": "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /c",
        "created_by_process": "services.exe",
        "created_by_pid": 700,
        "user": "SYSTEM",
        "host": "WKS-USER1-PC",
    }

    finding = detect_scheduled_task_creation(event)

    assert finding is not None
    assert finding["rule_id"] == "WINHUNT-004"
    assert finding["rule_name"] == "Scheduled Task Created"
    assert finding["severity"] == "medium"
    assert finding["timestamp"] == event["timestamp"]
    assert finding["event_id"] == event["event_id"]
    assert finding["event_type"] == event["event_type"]
    assert finding["evidence"]["task_name"] == "GoogleUpdateTaskMachineCore"
    assert finding["evidence"]["action"] == event["action"]
    assert finding["evidence"]["user"] == "SYSTEM"


def test_detect_scheduled_task_creation_positive_variant():
    event = {
        "event_type": "scheduled_task",
        "event_id": 4698,
        "timestamp": "2026-09-15T09:20:00.000Z",
        "task_name": "WindowsUpdateSvcTask",
        "action": "C:\\Users\\user1\\AppData\\Local\\Temp\\wupdsvc.exe -install",
        "created_by_process": "wupdsvc.exe",
        "created_by_pid": 7222,
        "user": "user1",
        "host": "WKS-USER1-PC",
    }

    finding = detect_scheduled_task_creation(event)

    assert finding is not None
    assert finding["rule_id"] == "WINHUNT-004"
    assert finding["evidence"]["created_by_process"] == "wupdsvc.exe"


def test_detect_scheduled_task_creation_negative_non_scheduled_process_event():
    event = {
        "event_type": "process",
        "event_id": 1,
        "timestamp": "2026-09-15T09:30:00Z",
        "process": "powershell.exe",
        "pid": 1111,
    }

    assert detect_scheduled_task_creation(event) is None


def test_detect_scheduled_task_creation_negative_network_event():
    event = {
        "event_type": "network",
        "event_id": 3,
        "timestamp": "2026-09-15T09:31:00Z",
        "process": "services.exe",
    }

    assert detect_scheduled_task_creation(event) is None


def test_detect_scheduled_task_creation_negative_missing_event_type():
    event = {
        "event_id": 4698,
        "timestamp": "2026-09-15T09:32:00Z",
        "task_name": "ExampleTask",
    }

    assert detect_scheduled_task_creation(event) is None


def test_detect_scheduled_task_creation_negative_invalid_input_types():
    assert detect_scheduled_task_creation(None) is None
    assert detect_scheduled_task_creation([]) is None
    assert detect_scheduled_task_creation("not-a-dict") is None


def test_detect_scheduled_task_creation_positive_event_without_optional_fields():
    event = {
        "event_type": "scheduled_task",
        "event_id": 4698,
        "timestamp": "2026-09-15T09:33:00Z",
    }

    finding = detect_scheduled_task_creation(event)

    assert finding is not None
    assert finding["event_type"] == "scheduled_task"
    assert finding["evidence"] == {}


def test_detect_appdata_rule_positive_appdata_roaming():
    event = {
        "event_type": "process",
        "event_id": 101,
        "timestamp": "2026-09-15T11:00:00",
        "pid": 5001,
        "process": "C:\\Users\\User\\AppData\\Roaming\\backup.exe",
        "command_line": "C:\\Users\\User\\AppData\\Roaming\\backup.exe",
    }

    finding = detect_suspicious_executable_location(event)

    assert finding is not None
    assert finding["rule_id"] == "WINHUNT-003"
    assert finding["severity"] == "medium"
    assert finding["evidence"]["process"] == event["process"]
    assert finding["evidence"]["location"] == "AppData"


def test_detect_suspicious_executable_location_positive_appdata_local():
    event = {
        "event_type": "process",
        "event_id": 102,
        "timestamp": "2026-09-15T11:01:00",
        "pid": 5002,
        "process": "C:\\Users\\User\\AppData\\Local\\program.exe",
        "command_line": "C:\\Users\\User\\AppData\\Local\\program.exe",
    }

    finding = detect_suspicious_executable_location(event)

    assert finding is not None
    assert finding["evidence"]["location"] == "AppData"


def test_detect_suspicious_executable_location_positive_temp_under_appdata():
    event = {
        "event_type": "process",
        "event_id": 103,
        "timestamp": "2026-09-15T11:02:00",
        "pid": 5003,
        "process": "C:\\Users\\User\\AppData\\Local\\Temp\\update.exe",
        "command_line": "C:\\Users\\User\\AppData\\Local\\Temp\\update.exe",
    }

    finding = detect_suspicious_executable_location(event)

    assert finding is not None
    assert finding["evidence"]["location"] == "AppData"


def test_detect_suspicious_executable_location_positive_windows_temp():
    event = {
        "event_type": "process",
        "event_id": 104,
        "timestamp": "2026-09-15T11:03:00",
        "pid": 5004,
        "process": "C:\\Windows\\Temp\\payload.exe",
        "command_line": "C:\\Windows\\Temp\\payload.exe",
    }

    finding = detect_suspicious_executable_location(event)

    assert finding is not None
    assert finding["evidence"]["location"] == "Temp"


def test_detect_suspicious_executable_location_positive_case_insensitive_path():
    event = {
        "event_type": "process",
        "event_id": 105,
        "timestamp": "2026-09-15T11:04:00",
        "pid": 5005,
        "process": "C:\\Users\\User\\APPDATA\\Roaming\\UPDATE.EXE",
        "command_line": "C:\\Users\\User\\APPDATA\\Roaming\\UPDATE.EXE",
    }

    finding = detect_suspicious_executable_location(event)

    assert finding is not None
    assert finding["evidence"]["location"] == "AppData"


def test_detect_suspicious_executable_location_negative_bare_executable_name():
    event = {
        "event_type": "process",
        "event_id": 106,
        "timestamp": "2026-09-15T11:05:00",
        "pid": 5006,
        "process": "backup.exe",
        "command_line": "backup.exe",
    }

    assert detect_suspicious_executable_location(event) is None


def test_detect_suspicious_executable_location_negative_system32_executable():
    event = {
        "event_type": "process",
        "event_id": 107,
        "timestamp": "2026-09-15T11:06:00",
        "pid": 5007,
        "process": "C:\\Windows\\System32\\notepad.exe",
        "command_line": "C:\\Windows\\System32\\notepad.exe",
    }

    assert detect_suspicious_executable_location(event) is None


def test_detect_suspicious_executable_location_negative_program_files_executable():
    event = {
        "event_type": "process",
        "event_id": 108,
        "timestamp": "2026-09-15T11:07:00",
        "pid": 5008,
        "process": "C:\\Program Files\\App\\app.exe",
        "command_line": "C:\\Program Files\\App\\app.exe",
    }

    assert detect_suspicious_executable_location(event) is None


def test_detect_suspicious_executable_location_negative_appdata_non_executable():
    event = {
        "event_type": "process",
        "event_id": 109,
        "timestamp": "2026-09-15T11:08:00",
        "pid": 5009,
        "process": "C:\\Users\\User\\AppData\\Roaming\\script.ps1",
        "command_line": "C:\\Users\\User\\AppData\\Roaming\\script.ps1",
    }

    assert detect_suspicious_executable_location(event) is None


def test_detect_suspicious_executable_location_negative_temp_non_executable():
    event = {
        "event_type": "process",
        "event_id": 110,
        "timestamp": "2026-09-15T11:09:00",
        "pid": 5010,
        "process": "C:\\Windows\\Temp\\script.txt",
        "command_line": "C:\\Windows\\Temp\\script.txt",
    }

    assert detect_suspicious_executable_location(event) is None


def test_detect_suspicious_executable_location_negative_fake_appdata_substring():
    event = {
        "event_type": "process",
        "event_id": 111,
        "timestamp": "2026-09-15T11:10:00",
        "pid": 5011,
        "process": "C:\\Tools\\AppDataHelper\\program.exe",
        "command_line": "C:\\Tools\\AppDataHelper\\program.exe",
    }

    assert detect_suspicious_executable_location(event) is None


def test_detect_suspicious_executable_location_negative_fake_temp_substring():
    event = {
        "event_type": "process",
        "event_id": 112,
        "timestamp": "2026-09-15T11:11:00",
        "pid": 5012,
        "process": "C:\\Tools\\mytempdata\\program.exe",
        "command_line": "C:\\Tools\\mytempdata\\program.exe",
    }

    assert detect_suspicious_executable_location(event) is None


def test_detect_suspicious_executable_location_negative_non_process_event():
    event = {
        "event_type": "network",
        "event_id": 113,
        "timestamp": "2026-09-15T11:12:00",
        "pid": 5013,
        "process": "C:\\Users\\User\\AppData\\Roaming\\backup.exe",
        "command_line": "C:\\Users\\User\\AppData\\Roaming\\backup.exe",
    }

    assert detect_suspicious_executable_location(event) is None


def test_detect_suspicious_executable_location_negative_missing_process():
    event = {
        "event_type": "process",
        "event_id": 114,
        "timestamp": "2026-09-15T11:13:00",
        "pid": 5014,
        "command_line": "C:\\Users\\User\\AppData\\Roaming\\backup.exe",
    }

    assert detect_suspicious_executable_location(event) is None


def test_detect_suspicious_executable_location_negative_empty_process():
    event = {
        "event_type": "process",
        "event_id": 115,
        "timestamp": "2026-09-15T11:14:00",
        "pid": 5015,
        "process": "",
        "command_line": "C:\\Users\\User\\AppData\\Roaming\\backup.exe",
    }

    assert detect_suspicious_executable_location(event) is None


def test_detect_suspicious_executable_location_negative_desktop_executable():
    event = {
        "event_type": "process",
        "event_id": 116,
        "timestamp": "2026-09-15T11:15:00",
        "pid": 5016,
        "process": "C:\\Users\\User\\Desktop\\program.exe",
        "command_line": "C:\\Users\\User\\Desktop\\program.exe",
    }

    assert detect_suspicious_executable_location(event) is None


def test_detect_suspicious_executable_location_verifies_finding_fields():
    event = {
        "event_type": "process",
        "event_id": 117,
        "timestamp": "2026-09-15T11:16:00",
        "pid": 5017,
        "process": "C:\\Users\\User\\AppData\\Local\\Temp\\program.exe",
        "command_line": "C:\\Users\\User\\AppData\\Local\\Temp\\program.exe",
    }

    finding = detect_suspicious_executable_location(event)

    assert finding is not None
    assert finding["rule_id"] == "WINHUNT-003"
    assert finding["severity"] == "medium"
    assert finding["evidence"]["process"] == event["process"]
    assert finding["evidence"]["command_line"] == event["command_line"]
    assert "location" in finding["evidence"]
