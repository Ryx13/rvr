#!/usr/bin/env python3
"""
RVR — legacy entry shim
The real CLI lives in rvr.cli (installed as the `rvr` command via
pyproject.toml). This file remains so the global launcher and direct
`python main.py` invocations keep working unchanged.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from rvr.cli import main

if __name__ == "__main__":
    main()
