import json
from copy import deepcopy
from pathlib import Path

from app.parser import parse_process_events
from app.process_tree import build_process_tree, get_process_chain


DATA_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_events.json"


def test_build_process_tree_reconstructs_all_normalized_process_records():
    with DATA_PATH.open("r", encoding="utf-8") as handle:
        raw_events = json.load(handle)

    process_events = parse_process_events(raw_events)
    original_records = deepcopy(process_events)
    tree = build_process_tree(process_events)

    assert len(process_events) == 182
    assert len(tree["by_pid"]) == 182
    assert set(tree["by_pid"].keys()) == {record["pid"] for record in process_events}

    for record in process_events:
        assert record["pid"] in tree["by_pid"]
        assert tree["by_pid"][record["pid"]] == record

    assert process_events == original_records


def test_build_process_tree_tracks_parent_child_relationships():
    with DATA_PATH.open("r", encoding="utf-8") as handle:
        raw_events = json.load(handle)

    process_events = parse_process_events(raw_events)
    tree = build_process_tree(process_events)

    child_pid = 2420
    parent_pid = 2404

    assert tree["by_pid"][child_pid]["process"] == "powershell.exe"
    assert tree["by_pid"][child_pid]["parent_process"] == "winword.exe"
    assert tree["parent"][child_pid] == parent_pid
    assert child_pid in tree["children"][parent_pid]
    assert 2420 in tree["children"][2404]


def test_get_process_chain_for_word_to_powershell_relationship():
    with DATA_PATH.open("r", encoding="utf-8") as handle:
        raw_events = json.load(handle)

    tree = build_process_tree(parse_process_events(raw_events))
    chain = get_process_chain(tree, 2420)

    assert [record["process"] for record in chain] == [
        "wininit.exe",
        "winlogon.exe",
        "userinit.exe",
        "explorer.exe",
        "winword.exe",
        "powershell.exe",
    ]
    assert [record["pid"] for record in chain] == [500, 540, 612, 2012, 2404, 2420]


def test_get_process_chain_handles_longer_known_chain():
    with DATA_PATH.open("r", encoding="utf-8") as handle:
        raw_events = json.load(handle)

    tree = build_process_tree(parse_process_events(raw_events))
    chain = get_process_chain(tree, 2456)

    assert [record["process"] for record in chain] == [
        "wininit.exe",
        "winlogon.exe",
        "userinit.exe",
        "explorer.exe",
        "winword.exe",
        "powershell.exe",
        "cmd.exe",
        "rundll32.exe",
    ]
    assert [record["pid"] for record in chain] == [500, 540, 612, 2012, 2432, 2440, 2444, 2456]


def test_get_process_chain_returns_leaf_when_no_parent_is_known():
    with DATA_PATH.open("r", encoding="utf-8") as handle:
        raw_events = json.load(handle)

    tree = build_process_tree(parse_process_events(raw_events))
    chain = get_process_chain(tree, 500)

    assert [record["process"] for record in chain] == ["wininit.exe"]
    assert [record["pid"] for record in chain] == [500]


def test_get_process_chain_stops_on_cycle_without_infinite_loop():
    tree = {
        "by_pid": {
            1: {"pid": 1, "process": "alpha.exe", "parent_pid": 2},
            2: {"pid": 2, "process": "beta.exe", "parent_pid": 1},
        },
        "children": {1: [2], 2: [1]},
        "parent": {1: 2, 2: 1},
    }

    chain = get_process_chain(tree, 1)

    assert [record["pid"] for record in chain] == [2, 1]
    assert [record["process"] for record in chain] == ["beta.exe", "alpha.exe"]
