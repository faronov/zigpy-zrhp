from __future__ import annotations

import json
import pathlib
from typing import Any

VECTORS = pathlib.Path(__file__).parent / "vectors"


def load_vector(name: str) -> Any:
    return json.loads((VECTORS / name).read_text())
