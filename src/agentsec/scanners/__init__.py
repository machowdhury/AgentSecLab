"""External scanner evidence producers.

Scanners do not authorize. Do not import this package from
agentsec.mcp.authorize, policy, metadata_trust, or pipeline.
"""

from agentsec.scanners.models import ADAPTER_VERSION, EVIDENCE_CLASS, SCANNER_FINDING_IS_NOT_AUTHZ

__all__ = ["ADAPTER_VERSION", "EVIDENCE_CLASS", "SCANNER_FINDING_IS_NOT_AUTHZ"]
