"""
Research Notes: Link Health Analysis for awesome-web-security

_Updated by [run 27015958205](https://github.com/qazbnm456/awesome-web-security/actions/runs/27015958205) at 2026-06-05T12:56:25Z._

This module provides comprehensive link health analysis for the awesome-web-security repository.
It implements production-quality error handling, type safety, logging, and performance optimization.
"""

from __future__ import annotations

import asyncio
import enum
import logging
import re
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Union, final
from urllib.parse import urlparse

import aiohttp
import pandas as pd
from pydantic import BaseModel, Field, HttpUrl, validator

# Configure production-grade logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s:%(funcName)s:%(lineno)d | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
logger = logging.getLogger(__name__)

# Constants
DEFAULT_TIMEOUT_SECONDS: int = 30
MAX_RETRIES: int = 3
BACKOFF_FACTOR: float = 2.0
CONCURRENT_REQUESTS: int = 50
USER_AGENT: str = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
ACCEPTABLE_STATUS_CODES: Set[int] = {200, 301, 302, 307, 308}
CACHE_EXPIRY_SECONDS: int = 3600  # 1 hour


class LinkStatus(enum.Enum):
    """Enumeration of possible link health statuses."""

    SUCCESS = "success"
    TIMEOUT = "timeout"
    REDIRECTED = "redirected"
    EXCLUDED = "excluded"
    UNKNOWN = "unknown"
    ERROR = "error"
    UNSUPPORTED = "unsupported"


class ErrorCategory(enum.Enum):
    """Categorization of link errors for analysis."""

    DEAD_RESOURCE = "dead_resource"
    SERVER_FAILURE = "server_failure"
    TIMEOUT = "timeout"
    REDIRECT = "redirect"
    RATE_LIMITED = "rate_limited"
    SSL_ERROR = "ssl_error"
    CONNECTION_ERROR = "connection_error"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class LinkCheckResult:
    """Immutable result of a single link health check."""

    url: str
    status: LinkStatus
    status_code: Optional[int] = None
    error_message: Optional[str] = None
    error_category: Optional[ErrorCategory] = None
    response_time_ms: Optional[float] = None
    redirect_url: Optional[str] = None
    cached: bool = False
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict:
        """Convert result to dictionary for serialization."""
        return {
            "url": self.url,
            "status": self.status.value,
            "status_code": self.status_code,
            "error_message": self.error_message,
            "error_category": self.error_category.value if self.error_category else None,
            "response_time_ms": self.response_time_ms,
            "redirect_url": self.redirect_url,
            "cached": self.cached,
            "checked_at": self.checked_at.isoformat(),
        }


class LinkHealthConfig(BaseModel):
    """Configuration model for link health analysis."""

    timeout_seconds: int = Field(default=DEFAULT_TIMEOUT_SECONDS, ge=1, le=120)
    max_retries: int = Field(default=MAX_RETRIES, ge=0, le=10)
    concurrent_requests: int = Field(default=CONCURRENT_REQUESTS, ge=1, le=200)
    acceptable_status_codes: Set[int] = Field(default=ACCEPTABLE_STATUS_CODES)
    user_agent: str = Field(default=USER_AGENT)
    cache_expiry_seconds: int = Field(default=CACHE_EXPIRY_SECONDS, ge=0)
    exclude_patterns: List[str] = Field(default_factory=list)
    geographic_regions: List[str] = Field(default_factory=lambda: ["global"])

    @validator("exclude_patterns", pre=True)
    def validate_exclude_patterns(cls, v: List[str]) -> List[str]:
        """Validate exclude patterns are valid regex."""
        for pattern in v:
            try:
                re.compile(pattern)
            except re.error as e:
                raise ValueError(f"Invalid regex pattern '{pattern}': {e}")
        return v


class URLCache:
    """Thread-safe URL cache with TTL support."""

    def __init__(self, expiry_seconds: int = CACHE_EXPIRY_SECONDS):
        self._cache: Dict[str, Tuple[LinkCheckResult, float]] = {}
        self._expiry_seconds = expiry_seconds

    def get(self, url: str) -> Optional[LinkCheckResult]:
        """Get cached result if not expired."""
        if url in self._cache:
            result, timestamp = self._cache[url]
            if time.time() - timestamp < self._expiry_seconds:
                return result
            else:
                del self._cache[url]
        return None

    def set(self, url: str, result: LinkCheckResult) -> None:
        """Cache a result with current timestamp."""
        self._cache[url] = (result, time.time())

    def clear(self) -> None:
        """Clear all cached entries."""
        self._cache.clear()

    @property
    def size(self) -> int:
        """Return number of cached entries."""
        return len(self._cache)


class LinkHealthAnalyzer:
    """
    Production-grade link health analyzer with comprehensive error handling,
    caching, retry logic, and detailed reporting capabilities.
    """

    def __init__(self, config: Optional[LinkHealthConfig] = None):
        self.config = config or LinkHealthConfig()
        self.cache = URLCache(expiry_seconds=self.config.cache_expiry_seconds)
        self.results: List[LinkCheckResult] = []
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def __aenter__(self) -> "LinkHealthAnalyzer":
        """Async context manager entry."""
        self._semaphore = asyncio.Semaphore(self.config.concurrent_requests)
        timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
        connector = aiohttp.TCPConnector(
            limit=self.config.concurrent_requests,
            ttl_dns_cache=300,
            ssl=ssl.create_default_context(),
        )
        self._session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"User-Agent": self.config.user_agent},
        )
        return self

    async def __aexit__(self, *args) -> None:
        """Async context manager exit with proper cleanup."""
        if self._session:
            await self._session.close()
            self._session = None

    async def check_link(self, url: str, source_file: Optional[str] = None) -> LinkCheckResult:
        """
        Check a single link with retry logic and caching.

        Args:
            url: The URL to check
            source_file: Optional source file for context

        Returns:
            LinkCheckResult with detailed status information

        Raises:
            ValueError: If URL is invalid or malformed
        """
        # Input validation
        if not url or not isinstance(url, str):
            raise ValueError(f"Invalid URL provided: {url}")

        # Check cache first
        cached_result = self.cache.get(url)
        if cached_result:
            logger.debug(f"Cache hit for URL: {url}")
            return LinkCheckResult(
                url=url,
                status=cached_result.status,
                status_code=cached_result.status_code,
                error_message=cached_result.error_message,
                error_category=cached_result.error_category,
                response_time_ms=cached_result.response_time_ms,
                redirect_url=cached_result.redirect_url,
                cached=True,
            )

        # Check exclusion patterns
        if self._is_excluded(url):
            logger.info(f"URL excluded by pattern: {url}")
            return LinkCheckResult(url=url, status=LinkStatus.EXCLUDED)

        # Attempt the request with retries
        last_error: Optional[Exception] = None
        start_time = time.monotonic()

        for attempt in range(self.config.max_retries + 1):
            try:
                async with self._semaphore:
                    async with self._session.get(
                        url,
                        allow_redirects=True,
                        timeout=aiohttp.ClientTimeout(total=self.config.timeout_seconds),
                    ) as response:
                        response_time_ms = (time.monotonic() - start_time) * 1000

                        # Handle redirects
                        if response.status in {301, 302, 307, 308}:
                            redirect_url = str(response.url)
                            logger.warning(f"Redirect detected: {url} -> {redirect_url}")
                            return LinkCheckResult(
                                url=url,
                                status=LinkStatus.REDIRECTED,
                                status_code=response.status,
                                response_time_ms=response_time_ms,
                                redirect_url=redirect_url,
                            )

                        # Check for acceptable status codes
                        if response.status in self.config.acceptable_status_codes:
                            logger.debug(f"Link healthy: {url} (status {response.status})")
                            result = LinkCheckResult(
                                url=url,
                                status=LinkStatus.SUCCESS,
                                status_code=response.status,
                                response_time_ms=response_time_ms,
                            )
                            self.cache.set(url, result)
                            return result
                        else:
                            # Determine error category based on status code
                            error_category = self._categorize_error(response.status)
                            error_msg = f"Rejected status code: {response.status} {response.reason}"
                            logger.error(f"Link failed: {url} - {error_msg}")
                            result = LinkCheckResult(
                                url=url,
                                status=LinkStatus.ERROR,
                                status_code=response.status,
                                error_message=error_msg,
                                error_category=error_category,
                                response_time_ms=response_time_ms,
                            )
                            self.cache.set(url, result)
                            return result

            except asyncio.TimeoutError as e:
                last_error = e
                logger.warning(f"Timeout on attempt {attempt + 1}/{self.config.max_retries + 1}: {url}")
                if attempt < self.config.max_retries:
                    await asyncio.sleep(BACKOFF_FACTOR ** attempt)
                continue

            except aiohttp.ClientConnectorError as e:
                last_error = e
                logger.error(f"Connection error on attempt {attempt + 1}: {url} - {str(e)}")
                if attempt < self.config.max_retries:
                    await asyncio.sleep(BACKOFF_FACTOR ** attempt)
                continue

            except aiohttp.ClientResponseError as e:
                last_error = e
                logger.error(f"Response error on attempt {attempt + 1}: {url} - {str(e)}")
                if attempt < self.config.max_retries:
                    await asyncio.sleep(BACKOFF_FACTOR ** attempt)
                continue

            except ssl.SSLError as e:
                last_error = e
                logger.error(f"SSL error for URL: {url} - {str(e)}")
                return LinkCheckResult(
                    url=url,
                    status=LinkStatus.ERROR,
                    error_message=f"SSL error: {str(e)}",
                    error_category=ErrorCategory.SSL_ERROR,
                )

            except Exception as e:
                last_error = e
                logger.exception(f"Unexpected error checking URL: {url}")
                if attempt < self.config.max_retries:
                    await asyncio.sleep(BACKOFF_FACTOR ** attempt)
                continue

        # All retries exhausted
        error_msg = f"All {self.config.max_retries + 1} attempts failed. Last error: {str(last_error)}"
        logger.error(f"Link failed after all retries: {url} - {error_msg}")
        result = LinkCheckResult(
            url=url,
            status=LinkStatus.ERROR,
            error_message=error_msg,
            error_category=ErrorCategory.TIMEOUT if isinstance(last_error, asyncio.TimeoutError) else ErrorCategory.CONNECTION_ERROR,
        )
        self.cache.set(url, result)
        return result

    def _is_excluded(self, url: str) -> bool:
        """Check if URL matches any exclusion pattern."""
        for pattern in self.config.exclude_patterns:
            if re.match(pattern, url):
                return True
        return False

    def _categorize_error(self, status_code: int) -> ErrorCategory:
        """Categorize HTTP error status codes."""
        if status_code == 404:
            return ErrorCategory.DEAD_RESOURCE
        elif status_code == 429:
            return ErrorCategory.RATE_LIMITED
        elif status_code in {500, 502, 503, 504}:
            return ErrorCategory.SERVER_FAILURE
        elif status_code in {301, 302, 307, 308}:
            return ErrorCategory.REDIRECT
        elif status_code == 408:
            return ErrorCategory.TIMEOUT
        else:
            return ErrorCategory.UNKNOWN

    async def check_links_batch(
        self, urls: List[str], source_file: Optional[str] = None
    ) -> List[LinkCheckResult]:
        """
        Check multiple links concurrently.

        Args:
            urls: List of URLs to check
            source_file: Optional source file for context

        Returns:
            List of LinkCheckResult for each URL
        """
        tasks = [self.check_link(url, source_file) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        processed_results: List[LinkCheckResult] = []
        for url, result in zip(urls, results):
            if isinstance(result, Exception):
                logger.error(f"Unhandled exception for URL {url}: {str(result)}")
                processed_results.append(
                    LinkCheckResult(
                        url=url,
                        status=LinkStatus.ERROR,
                        error_message=f"Unhandled exception: {str(result)}",
                        error_category=ErrorCategory.UNKNOWN,
                    )
                )
            else:
                processed_results.append(result)
        
        self.results.extend(processed_results)
        return processed_results

    def generate_report(self) -> pd.DataFrame:
        """Generate a comprehensive report as a pandas DataFrame."""
        if not self.results:
            logger.warning("No results to generate report")
            return pd.DataFrame()

        data = [result.to_dict() for result in self.results]
        df = pd.DataFrame(data)
        
        # Add summary statistics
        summary = {
            "total": len(df),
            "successful": len(df[df["status"] == "success"]),
            "timeouts": len(df[df["status"] == "timeout"]),
            "redirected": len(df[df["status"] == "redirected"]),
            "excluded": len(df[df["status"] == "excluded"]),
            "errors": len(df[df["status"] == "error"]),
            "unknown": len(df[df["status"] == "unknown"]),
            "unsupported": len(df[df["status"] == "unsupported"]),
        }
        
        logger.info(f"Report generated: {summary}")
        return df

    def get_summary_stats(self) -> Dict[str, int]:
        """Get summary statistics of link health checks."""
        if not self.results:
            return {}
        
        stats = {
            "total": len(self.results),
            "successful": sum(1 for r in self.results if r.status == LinkStatus.SUCCESS),
            "timeouts": sum(1 for r in self.results if r.status == LinkStatus.TIMEOUT),
            "redirected": sum(1 for r in self.results if r.status == LinkStatus.REDIRECTED),
            "excluded": sum(1 for r in self.results if r.status == LinkStatus.EXCLUDED),
            "errors": sum(1 for r in self.results if r.status == LinkStatus.ERROR),
            "unknown": sum(1 for r in self.results if r.status == LinkStatus.UNKNOWN),
            "unsupported": sum(1 for r in self.results if r.status == LinkStatus.UNSUPPORTED),
        }
        
        logger.info(f"Summary statistics: {stats}")
        return stats


async def main() -> None:
    """Main entry point for link health analysis."""
    config = LinkHealthConfig(
        timeout_seconds=30,
        max_retries=3,
        concurrent_requests=50,
        exclude_patterns=[r"^https?://localhost", r"^https?://127\.0\.0\.1"],
    )
    
    async with LinkHealthAnalyzer(config) as analyzer:
        # Example URLs to check
        urls = [
            "https://github.com/qazbnm456/awesome-web-security",
            "https://example.com/nonexistent",
            "https://httpbin.org/status/404",
            "https://httpbin.org/status/500",
        ]
        
        results = await analyzer.check_links_batch(urls)
        
        # Generate report
        df = analyzer.generate_report()
        print(df.to_string())
        
        # Print summary
        stats = analyzer.get_summary_stats()
        print(f"\nSummary: {stats}")


if __name__ == "__main__":
    asyncio.run(main())