import pytest
import pathlib
from memory import EpisodicMemory, TranslationEvent

def test_episodic_memory_trims_excess_events(tmp_path):
    mem = EpisodicMemory(memory_dir=str(tmp_path), max_events=5)

    for i in range(10):
        event = TranslationEvent(
            event_id=f"evt-{i}",
            timestamp="2024-01-01T00:00:00Z",
            from_vendor="cisco",
            to_vendor="huawei",
            original_config="vlan 10",
            translated_config="vlan 10",
            summary="ok",
            user="test",
        )
        mem.record(event)

    # After 10 events with max_events=5, only 5 should remain in the file
    lines = tmp_path / "events.jsonl"
    assert lines.exists()
    count = len([l for l in lines.read_text().splitlines() if l.strip()])
    assert count == 5, f"Expected 5 events, got {count}"

def test_episodic_memory_unlimited_when_max_events_zero(tmp_path):
    mem = EpisodicMemory(memory_dir=str(tmp_path), max_events=0)  # 0 = unlimited

    for i in range(20):
        event = TranslationEvent(
            event_id=f"evt-{i}",
            timestamp="2024-01-01T00:00:00Z",
            from_vendor="cisco",
            to_vendor="huawei",
            original_config="vlan 10",
            translated_config="vlan 10",
            summary="ok",
            user="test",
        )
        mem.record(event)

    lines = tmp_path / "events.jsonl"
    count = len([l for l in lines.read_text().splitlines() if l.strip()])
    assert count == 20, f"Expected 20 events (unlimited), got {count}"