import pytest
import os

@pytest.fixture(autouse=True)
def setup_directories():
    os.makedirs("logs", exist_ok=True)
    os.makedirs("cache", exist_ok=True)
    os.makedirs("knowledge_base/walkthroughs", exist_ok=True)
    yield
    # cleanup is optional, CI machines reset anyway
