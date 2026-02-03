"""Pytest configuration for magic link authentication tests."""
import pytest
import sys
import os

# Add lambdas directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lambdas'))


def pytest_configure(config):
    """Register custom markers."""
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests (requires AWS infrastructure)"
    )
