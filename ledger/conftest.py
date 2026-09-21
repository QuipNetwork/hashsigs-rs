"""Ragger fixtures shared by Speculos and the explicit USB test target."""
import json
from pathlib import Path
import pytest
from ragger.conftest import configuration

configuration.OPTIONAL.BACKEND_SCOPE = "module"
pytest_plugins = ("ragger.conftest.base_conftest",)


def pytest_configure(config):
    if config.getoption("backend") not in ("speculos", "ledgerwallet"):
        raise pytest.UsageError("Use speculos or ledgerwallet for this app.")
    if config.getoption("device") != "apex_p":
        raise pytest.UsageError("This app is built for Nano Gen5 (apex_p).")


def pytest_collection_modifyitems(config, items):
    if config.getoption("backend") != "speculos":
        for item in items:
            if item.get_closest_marker("emulator_only"):
                item.add_marker(pytest.mark.skip(reason="Uses emulator UI controls or malformed transport frames"))


@pytest.fixture(scope="session")
def vectors():
    data = json.loads((Path(__file__).parent / "artifacts/vectors.json").read_text())
    assert data["schema"] == 1
    assert data["profile"] == "shrincs-256s-sha2"
    return data


@pytest.fixture
def client(backend):
    from app_client import AppClient
    client = AppClient(backend)
    client.cancel()
    return client
