# -*- coding: utf-8 -*-
from pathlib import Path


def test_requirements_include_runtime_yaml_dependency():
    requirements = (Path(__file__).resolve().parent.parent / "requirements.txt").read_text(encoding="utf-8")

    assert "PyYAML" in requirements


def test_service_script_supports_local_venv_and_local_probe_host():
    service = (Path(__file__).resolve().parent.parent / "scripts" / "service.sh").read_text(encoding="utf-8")

    assert ".venv-local" in service
    assert "PROBE_HOST" in service
    assert "127.0.0.1" in service
    assert 'GUNICORN_TIMEOUT="${GUNICORN_TIMEOUT:-600}"' in service


def test_web_app_direct_run_default_port_matches_service():
    web_app = (Path(__file__).resolve().parent.parent / "web_app.py").read_text(encoding="utf-8")

    assert 'get_int_setting("PORT", 5008' in web_app


def test_web_app_direct_run_default_host_is_all_interfaces():
    web_app = (Path(__file__).resolve().parent.parent / "web_app.py").read_text(encoding="utf-8")

    assert 'get_str_setting("HOST", "0.0.0.0"' in web_app
    assert "app.run(host=host, port=port" in web_app


def test_web_app_direct_run_does_not_hardcode_localhost_only():
    web_app = (Path(__file__).resolve().parent.parent / "web_app.py").read_text(encoding="utf-8")

    assert 'app.run(host="127.0.0.1"' not in web_app
