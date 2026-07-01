import pytest
import os

# Set testing environment variable early before any other module loads
os.environ.setdefault("TESTING", "true")

@pytest.fixture(autouse=True)
def disable_rate_limiting():
    os.environ["TESTING"] = "true"

@pytest.fixture(autouse=True)
def setup_directories():
    os.makedirs("logs", exist_ok=True)
    os.makedirs("cache", exist_ok=True)
    os.makedirs("knowledge_base/walkthroughs", exist_ok=True)
    yield
    # cleanup is optional, CI machines reset anyway

