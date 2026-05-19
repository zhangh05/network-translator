# -*- coding: utf-8 -*-
"""Pytest conftest: clear cache before test run to avoid test cross-contamination."""

import os
import shutil
import pytest


@pytest.fixture(autouse=True, scope="session")
def clear_cache():
    cache_dir = os.path.join(os.path.dirname(__file__), "..", "cache_data")
    if os.path.isdir(cache_dir):
        shutil.rmtree(cache_dir)
    yield
