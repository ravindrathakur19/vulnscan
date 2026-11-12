import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest


@pytest.fixture
def tmp_data_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("SECRET_KEY", "test-secret-key")
    return tmp_path


@pytest.fixture
def app(tmp_data_dir):
    """Fresh Flask app per test, bound to an isolated DATA_DIR."""
    import importlib
    import app as app_module
    importlib.reload(app_module)  # re-run create_app() with the test env vars
    app_module.app.config["TESTING"] = True
    return app_module.app


@pytest.fixture
def client(app):
    return app.test_client()
