"""
Backwards-compatible shim. Prefer `mediguard-dlp` CLI (via pyproject entry
point) or `python -m mediguard_dlp.server` for new installations.
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mediguard_dlp.server import main

if __name__ == "__main__":
    main()
