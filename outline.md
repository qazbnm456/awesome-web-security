"""
Link Health Report Generator for awesome-web-security.

This module generates comprehensive link health reports from raw link checking data.
It provides structured analysis, error categorization, and actionable recommendations.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple, Any, Union
from pathlib import Path
import json
import os
from contextlib import contextmanager
import time
from functools import lru_cache

# Configure module-level logger
logger = logging.getLogger(__name__)

# Constants
MAX_URL_LENGTH = 2048
VALID_HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"}
DEFAULT_TIMEOUT_SECONDS = 30
MAX_RETRIES = 3
RETRY_BACKOFF_FACTOR = 2.0


class ErrorCategory(enum.Enum):
    """Categorization of link check errors with severity levels."""

    HTTP_404 = ("HTTP 404 Not Found", "Critical", "Resources no longer available")
    TIMEOUT = ("Timeout", "High", "Resources may be temporarily or permanently unavailable")
    HTTP_5XX = ("HTTP 5xx Server Error", "Medium-High", "Server-side issues requiring monitoring")
    HTTP_3XX = ("HTTP 3xx Redirect", "Low", "Redirects that may need URL updates")
    CONNECTION_ERROR = ("Generic Connection Error", "High", "Network, DNS, or server unavailability")
    HTTP_999 = ("HTTP 999", "Medium", "Rate limiting or access denied")
    UNKNOWN = ("Unknown Error", "Medium", "Uncategorized error requiring investigation")

    def __init__(self, display_name: str, severity: str, impact: str) -> None:
        """Initialize error category with metadata."""
        self.display_name = display_name
        self.severity = severity
        self.impact = impact

    @classmethod
    def from_severity(cls, severity: str) -> Optional["ErrorCategory"]:
        """Get error category by severity level."""
        for category in cls:
            if category.severity == severity:
                return category
        return None

    @classmethod
    def critical_categories(cls) -> List["ErrorCategory"]:
        """Get all critical error categories."""
        return [cat for cat in cls if cat.severity == "Critical"]


@dataclass(frozen=True)
class LinkCheckResult:
    """Immutable data class representing a single link check result."""

    url: str
    status: str
    error_type: Optional[str] = None
    source_file: Optional[str] = None
    cached: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    response_time_ms: Optional[int] = None
    http_status_code: Optional[int] = None
    redirect_chain: Tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        """Validate input data after initialization."""
        if not self.url or not isinstance(self.url, str):
            raise ValueError("URL must be a non-empty string")
        if len(self.url) > MAX_URL_LENGTH:
            raise ValueError(f"URL exceeds maximum length of {MAX_URL_LENGTH} characters")
        if not self.status or not isinstance(self.status, str):
            raise ValueError("Status must be a non-empty string")
        if self.error_type is not None and not isinstance(self.error_type, str):
            raise ValueError("Error type must be a string or None")
        if self.response_time_ms is not None and self.response_time_ms < 0:
            raise ValueError("Response time cannot be negative")
        if self.http_status_code is not None and (self.http_status_code < 100 or self.http_status_code > 599):
            raise ValueError("HTTP status code must be between 100 and 599")
        if not isinstance(self.redirect_chain, tuple):
            raise ValueError("redirect_chain must be a tuple")

    @property
    def is_error(self) -> bool:
        """Check if this result represents an error."""
        return self.status in ("ERROR", "TIMEOUT")

    @property
    def is_redirect(self) -> bool:
        """Check if this result represents a redirect."""
        return self.status == "REDIRECTED" or len(self.redirect_chain) > 0

    @property
    def is_success(self) -> bool:
        """Check if this result represents a success."""
        return self.status == "SUCCESS"

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "url": self.url,
            "status": self.status,
            "error_type": self.error_type,
            "source_file": self.source_file,
            "cached": self.cached,
            "timestamp": self.timestamp.isoformat(),
            "response_time_ms": self.response_time_ms,
            "http_status_code": self.http_status_code,
            "redirect_chain": list(self.redirect_chain),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LinkCheckResult":
        """Create LinkCheckResult from dictionary."""
        return cls(
            url=data["url"],
            status=data["status"],
            error_type=data.get("error_type"),
            source_file=data.get("source_file"),
            cached=data.get("cached", False),
            timestamp=datetime.fromisoformat(data["timestamp"]) if "timestamp" in data else datetime.now(timezone.utc),
            response_time_ms=data.get("response_time_ms"),
            http_status_code=data.get("http_status_code"),
            redirect_chain=tuple(data.get("redirect_chain", [])),
        )


@dataclass(frozen=True)
class ReportMetadata:
    """Metadata about the report generation run."""

    run_id: str
    timestamp: datetime
    tool_name: str = "Link Checker"
    config: Dict[str, object] = field(default_factory=dict)
    version: str = "1.0.0"
    environment: Optional[str] = None

    def __post_init__(self) -> None:
        """Validate metadata fields."""
        if not self.run_id:
            raise ValueError("run_id must be non-empty")
        if not isinstance(self.timestamp, datetime):
            raise ValueError("timestamp must be a datetime object")
        if not self.tool_name:
            raise ValueError("tool_name must be non-empty")
        if not self.version:
            raise ValueError("version must be non-empty")

    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary for serialization."""
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp.isoformat(),
            "tool_name": self.tool_name,
            "config": self.config,
            "version": self.version,
            "environment": self.environment,
        }

    @classmethod
    def create_default(cls, run_id: Optional[str] = None) -> "ReportMetadata":
        """Create default metadata with current timestamp."""
        return cls(
            run_id=run_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
            timestamp=datetime.now(timezone.utc),
        )


@dataclass
class ReportStatistics:
    """Aggregate statistics for a link health report."""

    total: int = 0
    successful: int = 0
    timeouts: int = 0
    redirected: int = 0
    excluded: int = 0
    unknown: int = 0
    errors: int = 0
    unsupported: int = 0
    avg_response_time_ms: Optional[float] = None
    max_response_time_ms: Optional[int] = None
    min_response_time_ms: Optional[int] = None

    def __post_init__(self) -> None:
        """Validate statistics fields."""
        if self.total < 0:
            raise ValueError("total must be non-negative")
        if self.successful < 0:
            raise ValueError("successful must be non-negative")
        if self.errors < 0:
            raise ValueError("errors must be non-negative")

    @property
    def success_rate(self) -> float:
        """Calculate the overall success rate as a percentage."""
        if self.total == 0:
            return 0.0
        return round((self.successful / self.total) * 100, 1)

    @property
    def failure_rate(self) -> float:
        """Calculate the overall failure rate as a percentage."""
        if self.total == 0:
            return 0.0
        return round(((self.errors + self.timeouts) / self.total) * 100, 1)

    @property
    def total_failures(self) -> int:
        """Get total number of failures."""
        return self.errors + self.timeouts

    @property
    def health_score(self) -> float:
        """Calculate overall health score (0-100)."""
        if self.total == 0:
            return 0.0
        return round((self.successful / self.total) * 100, 1)

    def update_response_times(self, response_times: Sequence[Optional[int]]) -> None:
        """Update response time statistics."""
        valid_times = [t for t in response_times if t is not None]
        if valid_times:
            self.avg_response_time_ms = round(sum(valid_times) / len(valid_times), 2)
            self.max_response_time_ms = max(valid_times)
            self.min_response_time_ms = min(valid_times)

    def to_dict(self) -> Dict[str, object]:
        """Convert statistics to a dictionary for serialization."""
        return {
            "total": self.total,
            "successful": self.successful,
            "timeouts": self.timeouts,
            "redirected": self.redirected,
            "excluded": self.excluded,
            "unknown": self.unknown,
            "errors": self.errors,
            "unsupported": self.unsupported,
            "success_rate": self.success_rate,
            "failure_rate": self.failure_rate,
            "total_failures": self.total_failures,
            "health_score": self.health_score,
            "avg_response_time_ms": self.avg_response_time_ms,
            "max_response_time_ms": self.max_response_time_ms,
            "min_response_time_ms": self.min_response_time_ms,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReportStatistics":
        """Create ReportStatistics from dictionary."""
        return cls(
            total=data.get("total", 0),
            successful=data.get("successful", 0),
            timeouts=data.get("timeouts", 0),
            redirected=data.get("redirected", 0),
            excluded=data.get("excluded", 0),
            unknown=data.get("unknown", 0),
            errors=data.get("errors", 0),
            unsupported=data.get("unsupported", 0),
            avg_response_time_ms=data.get("avg_response_time_ms"),
            max_response_time_ms=data.get("max_response_time_ms"),
            min_response_time_ms=data.get("min_response_time_ms"),
        )


class ErrorAnalyzer:
    """Analyzes and categorizes link check errors."""

    # Mapping of error codes to categories
    ERROR_CATEGORY_MAP: Dict[str, ErrorCategory] = {
        "404": ErrorCategory.HTTP_404,
        "TIMEOUT": ErrorCategory.TIMEOUT,
        "521": ErrorCategory.HTTP_5XX,
        "526": ErrorCategory.HTTP_5XX,
        "301": ErrorCategory.HTTP_3XX,
        "307": ErrorCategory.HTTP_3XX,
        "999": ErrorCategory.HTTP_999,
    }

    # Extended error code mappings
    EXTENDED_ERROR_MAP: Dict[str, ErrorCategory] = {
        "400": ErrorCategory.HTTP_404,
        "401": ErrorCategory.HTTP_404,
        "403": ErrorCategory.HTTP_404,
        "500": ErrorCategory.HTTP_5XX,
        "502": ErrorCategory.HTTP_5XX,
        "503": ErrorCategory.HTTP_5XX,
        "504": ErrorCategory.HTTP_5XX,
        "302": ErrorCategory.HTTP_3XX,
        "303": ErrorCategory.HTTP_3XX,
        "308": ErrorCategory.HTTP_3XX,
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize ErrorAnalyzer with optional configuration."""
        self.config = config or {}
        self._error_cache: Dict[str, ErrorCategory] = {}
        logger.debug("ErrorAnalyzer initialized with config: %s", self.config)

    @classmethod
    def categorize_error(cls, error_type: Optional[str]) -> ErrorCategory:
        """
        Categorize an error type into a predefined category.

        Args:
            error_type: The error type string (e.g., "404", "TIMEOUT").

        Returns:
            The corresponding ErrorCategory, or UNKNOWN if not recognized.
        """
        if error_type is None:
            return ErrorCategory.CONNECTION_ERROR

        normalized = error_type.strip().upper()
        
        # Check primary map first
        if normalized in cls.ERROR_CATEGORY_MAP:
            return cls.ERROR_CATEGORY_MAP[normalized]
        
        # Check extended map
        if normalized in cls.EXTENDED_ERROR_MAP:
            return cls.EXTENDED_ERROR_MAP[normalized]
        
        # Try to parse as HTTP status code
        try:
            status_code = int(normalized)
            if 400 <= status_code < 500:
                return ErrorCategory.HTTP_404
            elif 500 <= status_code < 600:
                return ErrorCategory.HTTP_5XX
            elif 300 <= status_code < 400:
                return ErrorCategory.HTTP_3XX
        except ValueError:
            pass
        
        return ErrorCategory.UNKNOWN

    @lru_cache(maxsize=128)
    def categorize_error_cached(self, error_type: Optional[str]) -> ErrorCategory:
        """Cached version of categorize_error for performance."""
        return self.categorize_error(error_type)

    @classmethod
    def analyze_errors(cls, results: Sequence[LinkCheckResult]) -> Dict[ErrorCategory, List[LinkCheckResult]]:
        """
        Group link check results by error category.

        Args:
            results: Sequence of link check results to analyze.

        Returns:
            Dictionary mapping ErrorCategory to list of matching results.
        """
        categorized: Dict[ErrorCategory, List[LinkCheckResult]] = {
            category: [] for category in ErrorCategory
        }

        for result in results:
            if result.is_error or result.is_redirect:
                category = cls.categorize_error(result.error_type)
                categorized[category].append(result)

        return categorized

    @classmethod
    def get_error_summary(cls, results: Sequence[LinkCheckResult]) -> Dict[str, int]:
        """
        Get summary of error counts by category.

        Args:
            results: Sequence of link check results.

        Returns:
            Dictionary mapping error category names to counts.
        """
        categorized = cls.analyze_errors(results)
        return {
            category.display_name: len(results)
            for category, results in categorized.items()
            if results
        }

    @classmethod
    def get_priority_errors(cls, results: Sequence[LinkCheckResult], min_severity: str = "High") -> List[LinkCheckResult]:
        """
        Get errors with severity at or above the specified level.

        Args:
            results: Sequence of link check results.
            min_severity: Minimum severity level to include.

        Returns:
            List of high-priority error results.
        """
        severity_order = {"Critical": 0, "High": 1, "Medium-High": 2, "Medium": 3, "Low": 4}
        min_level = severity_order.get(min_severity, 3)
        
        priority_errors = []
        for result in results:
            if result.is_error:
                category = cls.categorize_error(result.error_type)
                if severity_order.get(category.severity, 3) <= min_level:
                    priority_errors.append(result)
        
        return priority_errors


class ReportGenerator:
    """Generates structured link health reports from raw data."""

    def __init__(self, metadata: ReportMetadata, statistics: ReportStatistics) -> None:
        """
        Initialize the report generator.

        Args:
            metadata: Metadata about the report run.
            statistics: Aggregate statistics for the report.

        Raises:
            ValueError: If metadata or statistics are invalid.
        """
        if not isinstance(metadata, ReportMetadata):
            raise ValueError("metadata must be a ReportMetadata instance")
        if not isinstance(statistics, ReportStatistics):
            raise ValueError("statistics must be a ReportStatistics instance")

        self.metadata = metadata
        self.statistics = statistics
        self._results: List[LinkCheckResult] = []
        self._error_analyzer = ErrorAnalyzer()
        self._generation_time: Optional[float] = None
        logger.info("ReportGenerator initialized with run_id: %s", metadata.run_id)

    def add_results(self, results: Sequence[LinkCheckResult]) -> None:
        """
        Add link check results to the report.

        Args:
            results: Sequence of link check results to add.

        Raises:
            ValueError: If any result is invalid.
        """
        for result in results:
            if not isinstance(result, LinkCheckResult):
                raise ValueError(f"Expected LinkCheckResult, got {type(result).__name__}")
            self._results.append(result)

        logger.debug("Added %d results to report", len(results))

    def clear_results(self) -> None:
        """Clear all results from the report."""
        self._results.clear()
        logger.debug("Cleared all results from report")

    @property
    def result_count(self) -> int:
        """Get the number of results in the report."""
        return len(self._results)

    def generate_executive_summary(self) -> Dict[str, object]:
        """
        Generate the executive summary section of the report.

        Returns:
            Dictionary containing executive summary data.
        """
        start_time = time.time()
        
        summary = {
            "purpose": "High-level overview of link health status for the awesome-web-security repository.",
            "total_links_checked": self.statistics.total,
            "overall_success_rate": self.statistics.success_rate,
            "total_failures": self.statistics.total_failures,
            "failure_rate": self.statistics.failure_rate,
            "redirects": self.statistics.redirected,
            "health_score": self.statistics.