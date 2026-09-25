"""Small adapter boundary. Plugins must not import the PDP."""

from __future__ import annotations

from typing import Protocol

from agentsec.external_evidence.contract import ExternalEvidence


class ExternalEvidenceAdapter(Protocol):
    """Read external output, normalize, preserve raw evidence, emit records.

    Adapters must not call CTRL-MCP-001, Attack Service, or Academy internals.
    """

    provider: str
    tool: str

    def records(self) -> tuple[ExternalEvidence, ...]:
        """Return zero or more normalized records. Unknown fields stay omitted."""
