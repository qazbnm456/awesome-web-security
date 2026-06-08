"""
Link Health Report Generator for awesome-web-security repository.
Generates comprehensive markdown reports from link check workflow data.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum, auto
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union, Any, Final

import requests
from pydantic import BaseModel, Field, ValidationError, field_validator, ConfigDict
from requests.exceptions import (
    RequestException,
    ConnectionError,
    Timeout,
    HTTPError,
    TooManyRedirects,
    SSLError,
)

# ---------------------------------------------------------------------------
# Configuration & Constants
# ---------------------------------------------------------------------------

REPORT_TEMPLATE: Final[str] = """# Link Health Report

**Repository:** awesome-web-security  
**Report Generated:** {generated_at}  
**Run ID:** [{run_id}]({run_url})

---

## Executive Summary

This report presents the results of a comprehensive link health check performed on the awesome-web-security repository. Out of **{total_links} total links** scanned, **{total_errors} errors** and **{total_timeouts} timeouts** were detected, representing a **{failure_rate:.1f}% failure rate**. The most affected file is `{worst_file}`, which alone accounts for {worst_file_errors} broken links. The predominant failure modes are **404 Not Found** errors and **generic connection errors**, indicating that many referenced resources have been moved, removed, or are no longer accessible.

Immediate attention is recommended for all 404 errors, as these resources are definitively unavailable. Timeouts and 500-series errors should be investigated next, as they may indicate temporary outages or server misconfigurations.

---

## Overall Statistics

| Status | Count | Percentage |
|---|---|---|
| 🔍 Total Links Checked | {total_links} | 100% |
| ✅ Successful | {successful} | {successful_pct:.1f}% |
| 🔀 Redirected | {redirected} | {redirected_pct:.1f}% |
| 👻 Excluded | {excluded} | {excluded_pct:.1f}% |
| 🚫 Errors | {errors} | {errors_pct:.1f}% |
| ⏳ Timeouts | {timeouts} | {timeouts_pct:.1f}% |
| ❓ Unknown | {unknown} | 0% |
| ⛔ Unsupported | {unsupported} | 0% |

**Total Failed (Errors + Timeouts): {total_failed} ({failure_rate:.1f}%)**

---

## Error Breakdown by Type

| Error Type | Count | Severity |
|---|---|---|
| 404 Not Found | ~{error_404_count} | 🔴 Critical |
| Generic Connection Error | ~{error_connection_count} | 🔴 Critical |
| 301 Moved Permanently (flagged) | ~{error_301_count} | 🟡 Moderate |
| 307 Temporary Redirect (flagged) | ~{error_307_count} | 🟡 Moderate |
| 521 Web Server Down | ~{error_521_count} | 🟠 High |
| 526 Invalid SSL Certificate | ~{error_526_count} | 🟠 High |
| 999 Unknown/Blocked | ~{error_999_count} | 🟠 High |
| Timeout | {timeouts} | 🟡 Moderate |

---

## Error Analysis by File

### {worst_file} — {worst_file_errors} Errors (Highest Priority)

This file contains the highest concentration of broken links in the repository. Errors include:

- **404 Not Found** — {worst_file_404} occurrences
- **Generic Connection Errors** — {worst_file_connection} occurrences
- **Timeouts** — {worst_file_timeouts} occurrences
- **301/307 Redirects** — {worst_file_redirects} occurrences
- **521/526 Server Errors** — {worst_file_server_errors} occurrences
- **999 Blocked** — {worst_file_999} occurrence(s)

**Recommendation:** Prioritize this file for link remediation. Many Japanese-language security resources appear to have been taken offline or moved without redirects.

### README.md — {readme_errors} Errors

The main README file has the highest absolute number of errors, though this is proportional to its larger link count. Errors include:

- **404 Not Found** — {readme_404} occurrences
- **Generic Connection Errors** — {readme_connection} occurrences
- **Timeouts** — {readme_timeouts} occurrences
- **521/526 Server Errors** — {readme_server_errors} occurrences
- **301/307 Redirects** — {readme_redirects} occurrences

**Recommendation:** Address 404 errors first, then investigate server errors which may indicate resources behind misconfigured CDNs or firewalls.

### Other Files — {other_errors} Errors

Errors distributed across additional documentation files, with similar patterns of 404 and connection errors.

---

## Prioritized Fix List

### Tier 1: Immediate Action (Critical — 404 Errors)

These links return 404 Not Found and point to resources that no longer exist. Each must be replaced with an updated URL or removed.

| # | File | URL (truncated) | Error |
|---|---|---|---|
{iter_1_items}

**Total Tier 1 Items: ~{tier_1_count}**

### Tier 2: High Priority (Connection Errors & Server Errors)

These links may be temporarily down or have changed their network configuration. Investigate before removing.

| # | File | URL (truncated) | Error |
|---|---|---|---|
{iter_2_items}

**Total Tier 2 Items: ~{tier_2_count}**

### Tier 3: Moderate Priority (Timeouts & Redirects)

Timeouts may be intermittent; redirects may need updating to direct links.

| # | File | URL (truncated) | Error |
|---|---|---|---|
{iter_3_items}

**Total Tier 3 Items: ~{tier_3_count}**

---

## Recommendations

1. **Automate Link Checking** — Integrate a link checker into the CI/CD pipeline to catch broken links before they are merged. Consider tools like `lychee`, `broken-link-checker`, or `htmlproofer`.

2. **Prioritize README-jp.md** — This file has the highest error density. Consider reviewing all Japanese-language resources for availability.

3. **Replace or Remove Dead Links** — For each 404 error, search for an updated URL. If none exists, remove the link and consider replacing it with an alternative resource.

4. **Investigate Server Errors** — 521 and 526 errors may indicate resources behind Cloudflare or other CDNs that are misconfigured. Contact resource maintainers if possible.

5. **Update Redirected Links** — Where possible, replace 301/307 redirects with the final destination URL to improve performance and reliability.

6. **Schedule Regular Audits** — Perform a full link health check monthly to maintain repository quality.

---

## Raw Error Details

For a complete list of all errors with full URLs, refer to the raw output from the workflow run:  
[{run_id}]({run_url})

---

*Report generated automatically by the awesome-web-security link health check workflow.*
"""

# ---------------------------------------------------------------------------
# Logging Configuration
# ---------------------------------------------------------------------------

def setup_logging(level: int = logging.INFO) -> None:
    """Configure structured logging for the application.

    Args:
        level: Logging level (default: logging.INFO)

    Raises:
        ValueError: If an invalid logging level is provided
    """
    if not isinstance(level, int) or level < logging.DEBUG or level > logging.CRITICAL:
        raise ValueError(f"Invalid logging level: {level}")

    try:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
            handlers=[
                logging.StreamHandler(sys.stdout),
                logging.FileHandler("link_health_report.log", mode="w", encoding="utf-8"),
            ],
        )
    except (OSError, PermissionError) as e:
        logging.basicConfig(
            level=level,
            format="%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
            handlers=[logging.StreamHandler(sys.stdout)],
        )
        logging.warning(f"Could not create log file: {e}. Logging to stdout only.")

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums & Data Models
# ---------------------------------------------------------------------------

class LinkStatus(Enum):
    """Enumeration of possible link check statuses."""
    SUCCESS = auto()
    REDIRECTED = auto()
    EXCLUDED = auto()
    ERROR = auto()
    TIMEOUT = auto()
    UNKNOWN = auto()
    UNSUPPORTED = auto()


class ErrorSeverity(Enum):
    """Severity levels for link errors."""
    CRITICAL = "🔴 Critical"
    HIGH = "🟠 High"
    MODERATE = "🟡 Moderate"


@dataclass
class LinkCheckResult:
    """Represents the result of checking a single link.

    Attributes:
        url: The URL that was checked
        status: The status of the link check
        error_type: Type of error if status is ERROR
        http_status_code: HTTP status code if applicable
        file_path: Path to the file containing this link
        is_cached: Whether this result came from cache
        timestamp: When the check was performed
    """
    url: str
    status: LinkStatus
    error_type: Optional[str] = None
    http_status_code: Optional[int] = None
    file_path: Optional[str] = None
    is_cached: bool = False
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        """Validate the dataclass fields after initialization."""
        if not self.url or not isinstance(self.url, str):
            raise ValueError("URL must be a non-empty string")
        if not isinstance(self.status, LinkStatus):
            raise ValueError(f"Invalid status: {self.status}")
        if self.http_status_code is not None and (self.http_status_code < 100 or self.http_status_code > 599):
            raise ValueError(f"Invalid HTTP status code: {self.http_status_code}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a dictionary for serialization.

        Returns:
            Dictionary representation of the link check result
        """
        return {
            "url": self.url,
            "status": self.status.name,
            "error_type": self.error_type,
            "http_status_code": self.http_status_code,
            "file_path": self.file_path,
            "is_cached": self.is_cached,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LinkCheckResult":
        """Create a LinkCheckResult from a dictionary.

        Args:
            data: Dictionary containing link check result data

        Returns:
            A new LinkCheckResult instance

        Raises:
            KeyError: If required keys are missing
            ValueError: If data contains invalid values
        """
        required_keys = {"url", "status"}
        missing_keys = required_keys - set(data.keys())
        if missing_keys:
            raise KeyError(f"Missing required keys: {missing_keys}")

        return cls(
            url=data["url"],
            status=LinkStatus[data["status"]],
            error_type=data.get("error_type"),
            http_status_code=data.get("http_status_code"),
            file_path=data.get("file_path"),
            is_cached=data.get("is_cached", False),
            timestamp=datetime.fromisoformat(data.get("timestamp", datetime.now(timezone.utc).isoformat())),
        )


class ReportData(BaseModel):
    """Pydantic model for report data validation."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    total_links: int = Field(ge=0, description="Total number of links checked")
    successful: int = Field(ge=0, description="Number of successful checks")
    redirected: int = Field(ge=0, description="Number of redirects")
    excluded: int = Field(ge=0, description="Number of excluded links")
    errors: int = Field(ge=0, description="Number of errors")
    timeouts: int = Field(ge=0, description="Number of timeouts")
    unknown: int = Field(ge=0, description="Number of unknown statuses")
    unsupported: int = Field(ge=0, description="Number of unsupported links")
    run_id: str = Field(min_length=1, description="GitHub Actions run ID")
    run_url: str = Field(min_length=1, description="URL to the workflow run")
    generated_at: str = Field(min_length=1, description="Timestamp of report generation")

    @field_validator("run_url")
    @classmethod
    def validate_run_url(cls, v: str) -> str:
        """Validate that run_url is a proper URL."""
        if not v.startswith(("http://", "https://")):
            raise ValueError("run_url must be a valid HTTP/HTTPS URL")
        return v

    @field_validator("generated_at")
    @classmethod
    def validate_timestamp(cls, v: str) -> str:
        """Validate that generated_at is a proper ISO timestamp."""
        try:
            datetime.fromisoformat(v)
        except (ValueError, TypeError):
            raise ValueError("generated_at must be a valid ISO timestamp")
        return v


class ErrorItem(BaseModel):
    """Pydantic model for error items in the report."""
    model_config = ConfigDict(extra="forbid", frozen=True)

    index: int = Field(ge=1, description="Error item index")
    file: str = Field(min_length=1, description="File containing the error")
    url: str = Field(min_length=1, description="URL with error")
    error: str = Field(min_length=1, description="Error description")

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        """Validate that url is a proper URL."""
        if not v.startswith(("http://", "https://", "ftp://", "ftps://")):
            raise ValueError("url must be a valid URL")
        return v


# ---------------------------------------------------------------------------
# Error Parser
# ---------------------------------------------------------------------------

class ErrorParser:
    """Parses error data from the workflow output."""

    # Error pattern constants
    ERROR_PATTERN: Final[re.Pattern] = re.compile(
        r'\[(ERROR|TIMEOUT|404|301|307|521|526|999)\]\s*\|\s*(.*?)(?:\s*\(cached\))?$',
        re.MULTILINE
    )
    FILE_HEADER_PATTERN: Final[re.Pattern] = re.compile(
        r'^### Errors in (.+)$',
        re.MULTILINE
    )
    CACHED_PATTERN: Final[re.Pattern] = re.compile(r'\(cached\)', re.IGNORECASE)
    TIMEOUT_PATTERN: Final[re.Pattern] = re.compile(r'\[TIMEOUT\]', re.IGNORECASE)
    ERROR_CODE_PATTERN: Final[re.Pattern] = re.compile(r'\[(\d{3})\]')

    def __init__(self, log_file_path: Optional[str] = None) -> None:
        """Initialize the ErrorParser.

        Args:
            log_file_path: Optional path to a log file for debugging
        """
        self.log_file_path = log_file_path
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Set up logging for the parser."""
        self.logger = logging.getLogger(f"{__name__}.ErrorParser")

    def parse_errors(self, content: str) -> Dict[str, List[LinkCheckResult]]:
        """Parse error content from the workflow output.

        Args:
            content: Raw error content from the workflow

        Returns:
            Dictionary mapping file paths to lists of LinkCheckResult objects

        Raises:
            ValueError: If content is empty or invalid
        """
        if not content or not isinstance(content, str):
            raise ValueError("Content must be a non-empty string")

        errors_by_file: Dict[str, List[LinkCheckResult]] = {}
        current_file: Optional[str] = None

        try:
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                if not line:
                    continue

                # Check for file header
                file_match = self.FILE_HEADER_PATTERN.match(line)
                if file_match:
                    current_file = file_match.group(1).strip()
                    if current_file not in errors_by_file:
                        errors_by_file[current_file] = []
                    continue

                # Check for error line
                error_match = self.ERROR_PATTERN.match(line)
                if error_match and current_file:
                    error_type = error_match.group(1)
                    url_part = error_match.group(2).strip()

                    # Determine status and details
                    is_cached = bool(self.CACHED_PATTERN.search(line))
                    is_timeout = bool(self.TIMEOUT_PATTERN.search(line))

                    if is_timeout:
                        status = LinkStatus.TIMEOUT
                        http_code = None
                    else:
                        status = LinkStatus.ERROR
                        http_code = self._extract_http_code(error_type)

                    result = LinkCheckResult(
                        url=url_part,
                        status=status,
                        error_type=error_type,
                        http_status_code=http_code,
                        file_path=current_file,
                        is_cached=is_cached,
                    )
                    errors_by_file[current_file].append(result)

            self.logger.info(f"Parsed {sum(len(v) for v in errors_by_file.values())} errors from {len(errors_by_file)} files")
            return errors_by_file

        except Exception as e:
            self.logger.error(f"Error parsing content: {e}")
            raise

    def _extract_http_code(self, error_type: str) -> Optional[int]:
        """Extract HTTP status code from error type string.

        Args:
            error_type: Error type string (e.g., "404", "ERROR")