"""Make sibling folders importable.

detection-engine imports SecurityEvent from event-generator, and its own
modules import each other. Import this module first in any script or test
in this folder.
"""

import sys
from pathlib import Path

ENGINE_DIR = Path(__file__).resolve().parent
REPO_ROOT = ENGINE_DIR.parent
EVENT_GENERATOR_DIR = REPO_ROOT / "event-generator"
RAW_DATA_DIR = REPO_ROOT / "data" / "raw"

for folder in (ENGINE_DIR, EVENT_GENERATOR_DIR):
    if str(folder) not in sys.path:
        sys.path.insert(0, str(folder))