import pytest
from core.semantic_compare import SemanticComparator, IRBlock

def test_empty_ir_returns_no_match():
    comp = SemanticComparator()
    result = comp.compare([], [])
    assert result["overall_match"] is False
    assert result["matched_blocks"] == []

def test_single_type_match():
    comp = SemanticComparator()
    source = [
        IRBlock(type="vlan", function="create vlan", params={"id": 10, "name": "VLAN10"}, original_lines=["vlan 10"], confidence=1.0),
    ]
    translated = [
        {"type": "vlan", "original_lines": ["vlan 10"], "translated_lines": ["vlan 10"], "confidence": 1.0},
    ]
    result = comp.compare(source, translated)
    assert result["overall_match"] is True
    assert len(result["matched_blocks"]) == 1
    assert result["matched_blocks"][0]["type"] == "vlan"
    assert result["matched_blocks"][0]["match"] is True

def test_missing_translated_block_fails():
    comp = SemanticComparator()
    source = [
        IRBlock(type="vlan", function="create vlan", params={"id": 10}, original_lines=["vlan 10"], confidence=1.0),
        IRBlock(type="bgp", function="bgp as", params={"asn": 65001}, original_lines=["router bgp 65001"], confidence=1.0),
    ]
    translated = [
        {"type": "vlan", "original_lines": ["vlan 10"], "translated_lines": ["vlan 10"], "confidence": 1.0},
        # bgp block missing — should mark as fail
    ]
    result = comp.compare(source, translated)
    assert result["overall_match"] is False
    assert len(result["unmatched_source"]) == 1
    assert "bgp" in result["unmatched_source"]

def test_params_field_coverage_scores():
    comp = SemanticComparator()
    source = [
        IRBlock(type="interface", function="layer3 interface", params={"name": "GigabitEthernet0/1", "ip": "10.0.0.1", "mask": "255.255.255.0"}, original_lines=["interface GigabitEthernet0/1"], confidence=1.0),
    ]
    translated = [
        {"type": "interface", "original_lines": ["interface GigabitEthernet0/1"], "translated_lines": ["interface GigabitEthernet0/1", "ip address 10.0.0.1 255.255.255.0"], "confidence": 1.0},
    ]
    result = comp.compare(source, translated)
    assert result["overall_match"] is True
    # similarity reflects keyword overlap between source params and translated_lines text:
    # source keywords: {"gigabitethernet0/1", "10.0.0.1", "255.255.255.0"}
    # translated_lines words: "interface", "gigabitethernet0/1", "ip", "address", "10.0.0.1", "255.255.255.0"
    # overlap = 3 (name, ip, mask as strings appear), so similarity = 3/3 = 1.0
    assert 0.5 <= result["matched_blocks"][0]["similarity"] <= 1.0

def test_empty_translated_lines_fails_block():
    comp = SemanticComparator()
    source = [
        IRBlock(type="acl", function="permit http", params={"acl_id": 101}, original_lines=["access-list 101 permit tcp any any eq 80"], confidence=1.0),
    ]
    translated = [
        {"type": "acl", "original_lines": ["access-list 101 permit tcp any any eq 80"], "translated_lines": [], "notes": "no equivalent in target", "confidence": 0.3},
    ]
    result = comp.compare(source, translated)
    assert result["matched_blocks"][0]["match"] is False
    assert result["matched_blocks"][0]["similarity"] < 0.5


def test_translate_node_uses_semantic_comparator(monkeypatch):
    from core.graph import State
    from core.graph.nodes import TranslateNode

    call_count = [0]

    class FakeLLM:
        def chat(self, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return {
                    "content": '[{"type":"vlan","function":"create vlan","params":{"id":10},"original_lines":["vlan 10"],"confidence":1.0}]'
                }
            return {
                "content": '[{"type":"vlan","original_lines":["vlan 10"],"translated_lines":[],"confidence":0.0}]'
            }

    from core import semantic_compare
    original = semantic_compare.SemanticComparator.compare

    def patched_compare(self, ir_source, ir_translation):
        # Verify inputs are non-empty lists
        assert isinstance(ir_source, list) and len(ir_source) > 0
        assert isinstance(ir_translation, list) and len(ir_translation) > 0
        return {"overall_match": False, "matched_blocks": [], "unmatched_source": ["vlan"], "summary": "patched"}

    monkeypatch.setattr(semantic_compare.SemanticComparator, "compare", patched_compare)

    llm = FakeLLM()
    state = State()
    state.set("config_text", "vlan 10")
    state.set("from_vendor", "cisco")
    state.set("to_vendor", "huawei")

    result = TranslateNode(llm=llm).execute(state)

    assert result.is_success()
    # Verify lightweight heuristic is NOT used
    assert state.get("ir_compare", {}).get("summary") == "patched"
