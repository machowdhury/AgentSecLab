"""JSON decoder that rejects duplicate object keys.

Default json.loads last-wins. Authorization identifiers must not silently
become a different value because a duplicate key appeared later in the body.
"""

from __future__ import annotations

import json
from typing import Any


class DuplicateJsonKeyError(ValueError):
    """Raised when a JSON object contains the same key more than once."""


def loads_json_no_duplicate_keys(text: str) -> Any:
    """Parse JSON. Duplicate keys at any object nesting level raise DuplicateJsonKeyError."""

    def object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: dict[str, Any] = {}
        for key, value in pairs:
            if key in seen:
                raise DuplicateJsonKeyError(key)
            seen[key] = value
        return seen

    return json.loads(text, object_pairs_hook=object_pairs_hook)
