from pathlib import Path
import builtins
import io
import json

import pytest

from core import LLM
from core.ir import _extract_json_array, _extract_json_object


def test_extract_json_array_handles_markdown_and_trailing_text():
    content = """
Here is the result:

```json
[
  {"type": "interface", "translated_lines": ["interface XGigabitEthernet0/1"]}
]
```

done
"""

    assert _extract_json_array(content) == [
        {"type": "interface", "translated_lines": ["interface XGigabitEthernet0/1"]}
    ]


def test_extract_json_array_uses_first_valid_array_when_multiple_arrays_exist():
    content = 'notes [not json] then [{"type": "vlan", "params": {"id": 10}}] tail [{"bad": true}]'

    assert _extract_json_array(content) == [{"type": "vlan", "params": {"id": 10}}]


def test_extract_json_object_handles_markdown_object():
    content = """```json
{"overall_match": true, "summary": "ok"}
```"""

    assert _extract_json_object(content) == {"overall_match": True, "summary": "ok"}


def test_knowledge_retrieval_uses_cache_until_cleared(tmp_path, monkeypatch):
    import tools.knowledge_manager as km

    knowledge_root = tmp_path / "knowledge_data"
    vendor_dir = knowledge_root / "huawei"
    vendor_dir.mkdir(parents=True)
    topic = vendor_dir / "vlan.md"
    topic.write_text("first", encoding="utf-8")

    monkeypatch.setattr(km, "KNOWLEDGE_DIR", knowledge_root)
    km.clear_knowledge_cache()

    assert km.retrieve_knowledge({"type": "vlan"}, "huawei") == "first"
    topic.write_text("second", encoding="utf-8")
    assert km.retrieve_knowledge({"type": "vlan"}, "huawei") == "first"

    km.clear_knowledge_cache()
    assert km.retrieve_knowledge({"type": "vlan"}, "huawei") == "second"


def test_llm_test_route_reports_success(tmp_path, monkeypatch):
    flask = pytest.importorskip("flask")
    import llm_settings
    from web_app import create_app

    class FakeLLM:
        def chat(self, **kwargs):
            return {"content": "OK_CONNECTIVITY_TEST"}

    monkeypatch.setattr(llm_settings, "create_llm_from_settings", lambda: FakeLLM())
    settings_file = tmp_path / "llmsetting.json"
    settings_file.write_text(json.dumps({
        "api_key": "test-key",
        "model": "MiniMax-M2.7",
        "base_url": "https://api.minimaxi.com/anthropic",
        "timeout": 45,
    }), encoding="utf-8")
    monkeypatch.setenv("LLM_SETTINGS_FILE", str(settings_file))

    app = create_app()
    client = app.test_client()
    resp = client.post("/api/llm/test")

    assert resp.status_code == 200
    assert resp.json["ok"] is True


def test_llm_chat_falls_back_to_urllib_when_requests_is_missing(monkeypatch):
    original_import = builtins.__import__

    def guarded_import(name, *args, **kwargs):
        if name == "requests":
            raise ImportError("No module named requests")
        return original_import(name, *args, **kwargs)

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            payload = {"choices": [{"message": {"content": "ok"}}]}
            return json.dumps(payload).encode("utf-8")

    def fake_urlopen(request, timeout):
        return FakeResponse()

    monkeypatch.setattr(builtins, "__import__", guarded_import)
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = LLM(api_key="key", base_url="http://llm.test").chat(
        messages=[{"role": "user", "content": "ping"}]
    )

    assert result["content"] == "ok"


def test_llm_chat_supports_anthropic_compatible_endpoint(monkeypatch):
    captured = {}

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            payload = {"content": [{"type": "text", "text": '[{"type":"test"}]'}]}
            return json.dumps(payload).encode("utf-8")

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["headers"] = dict(request.header_items())
        captured["body"] = json.loads(request.data.decode("utf-8"))
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)

    result = LLM(api_key="key", base_url="https://api.minimaxi.com/anthropic").chat(
        messages=[{"role": "user", "content": "ping"}],
        system="system prompt",
        max_tokens=123,
    )

    assert captured["url"] == "https://api.minimaxi.com/anthropic/v1/messages"
    assert captured["headers"]["X-api-key"] == "key"
    assert captured["body"]["system"] == "system prompt"
    assert captured["body"]["max_tokens"] == 123
    assert result["content"] == '[{"type":"test"}]'


def test_translate_node_light_path_uses_one_llm_call():
    from core.graph import State
    from core.graph.nodes import TranslateNode

    class FakeLLM:
        def __init__(self):
            self.calls = 0

        def chat(self, **kwargs):
            self.calls += 1
            return {
                "content": '[{"type":"interface","original_lines":["interface GigabitEthernet0/1"," switchport mode trunk"],"translated_lines":["interface XGigabitEthernet0/1"," port link-type trunk"],"notes":"","confidence":1.0}]'
            }

    llm = FakeLLM()
    state = State()
    state.set("config_text", "interface GigabitEthernet0/1\n switchport mode trunk")
    state.set("from_vendor", "cisco")
    state.set("to_vendor", "huawei")

    result = TranslateNode(llm=llm).execute(state)

    assert result.is_success()
    assert llm.calls == 1
    assert "interface XGigabitEthernet0/1" in state.get("translated_config")
    assert state.get("ir_compare")["overall_match"] is True


def test_llm_retry_on_transient_http_error(monkeypatch):
    call_count = [0]

    class FakeResp:
        status_code = 502
        text = "Bad Gateway"

    def fake_post(url, headers=None, json=None, timeout=None):
        call_count[0] += 1
        return FakeResp()

    import requests as _real_requests
    monkeypatch.setattr(_real_requests, "post", fake_post)
    llm = LLM(api_key="test", base_url="https://fake.example.com/v1", max_retries=1)
    result = llm.chat(messages=[{"role": "user", "content": "hi"}])
    assert "error" in result
    assert call_count[0] == 2  # 1 initial + 1 retry


def test_llm_max_retries_not_exceeded_on_success(monkeypatch):
    call_count = [0]

    class FakeResp:
        status_code = 200
        def json(self):
            return {"choices": [{"message": {"content": "ok"}}]}

    def fake_post(url, headers=None, json=None, timeout=None):
        call_count[0] += 1
        return FakeResp()

    import requests as _real_requests
    monkeypatch.setattr(_real_requests, "post", fake_post)
    llm = LLM(api_key="test", base_url="https://fake.example.com/v1", max_retries=2)
    result = llm.chat(messages=[{"role": "user", "content": "hi"}])
    assert result.get("content") == "ok"
    assert call_count[0] == 1  # no retry on success


def test_is_retryable_error():
    llm = LLM()
    assert llm._is_retryable_error("429 Too Many Requests")
    assert llm._is_retryable_error("500 Internal Server Error")
    assert llm._is_retryable_error("timeout")
    assert llm._is_retryable_error("Connection refused")
    assert not llm._is_retryable_error("400 Bad Request")
    assert not llm._is_retryable_error("401 Unauthorized")


def test_knowledge_cache_ttl():
    from tools.knowledge_manager import _read_knowledge_file, clear_knowledge_cache, KNOWLEDGE_DIR
    clear_knowledge_cache()
    path = KNOWLEDGE_DIR / "cisco" / "vlan.md"
    if not path.exists():
        pytest.skip("knowledge file not found")
    content1 = _read_knowledge_file(path)
    assert content1
    content2 = _read_knowledge_file(path)
    assert content2 == content1  # cached


def test_tokenize_word_boundaries():
    from core.semantic_compare import _tokenize
    assert _tokenize("ip address 10.0.0.1 255.255.255.0") == {"ip", "address", "10", "0", "0", "1", "255"}
    assert _tokenize("interface GigabitEthernet0/1") == {"interface", "gigabitethernet0", "1"}
    assert _tokenize("") == set()
