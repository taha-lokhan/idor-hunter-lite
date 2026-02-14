"""
Data models for scan results and stats.
"""
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class ScanResult:
    """Single result for an IDOR request."""
    id: int
    url: str
    status: Optional[int] = None
    body: Optional[str] = None
    body_len: int = 0
    error: Optional[str] = None
    # diff fields
    diff_status: Optional[bool] = None  # differs from baseline status
    diff_len: Optional[bool] = None    # differs from baseline length


@dataclass
class ScanStats:
    """Statistics for an IDOR scan."""
    total: int
    success: int
    errors: int
    status_changes: int
    length_changes: int

    def as_dict(self) -> Dict[str, int]:
        return {
            "total": self.total,
            "success": self.success,
            "errors": self.errors,
            "status_changes": self.status_changes,
            "length_changes": self.length_changes,
        }
