"""
Coverage auto-start module for test containers.

This module is automatically imported by Python at interpreter startup via a .pth file.
It initializes coverage collection for the operator running inside containers during
integration tests.

The coverage data is stored in /tmp/.coverage.* files which are retrieved after tests
complete and combined with unit test coverage for a complete coverage report.
"""

import os
import sys


def start_coverage():
    """Start coverage collection if COVERAGE_PROCESS_START is set."""
    coverage_config = os.environ.get("COVERAGE_PROCESS_START")

    if not coverage_config:
        # Coverage not enabled, skip
        return

    try:
        import coverage
    except ImportError:
        print(
            "WARNING: coverage package not installed, cannot collect coverage data",
            file=sys.stderr,
        )
        return

    # Check if coverage is already running (e.g., via 'coverage run' command)
    # This prevents double initialization which causes coverage to not measure any files
    if coverage.Coverage.current() is not None:
        print(
            "Coverage already running (started by 'coverage run'), skipping sitecustomize initialization",
            file=sys.stderr,
        )
        return

    # Start coverage collection
    # This will read config from COVERAGE_PROCESS_START path
    coverage.process_startup()
    print(f"Coverage collection started (config: {coverage_config})", file=sys.stderr)


# Auto-start coverage when module is imported
start_coverage()
