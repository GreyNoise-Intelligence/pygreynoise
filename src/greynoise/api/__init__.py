"""GreyNoise API client."""

import logging
import re
import time
from collections import OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Union
from urllib.parse import urlencode, urljoin

import cachetools
import more_itertools
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from greynoise.__version__ import __version__
from greynoise.api.filter import Filter
from greynoise.exceptions import RateLimitError, RequestFailure
from greynoise.greynoise_timeline import get_greynoise_timeline
from greynoise.util import (
    normalize_rfc3339_datetime,
    validate_cve_id,
    validate_ip,
    validate_timeline_days,
    validate_timeline_field_value,
    validate_timeline_granularity,
)

LOGGER = logging.getLogger(__name__)


def _api_request_url(api_server: Optional[str], endpoint: str) -> str:
    """Build an absolute request URL from ``api_server`` and path ``endpoint``."""

    base = (api_server or "").rstrip("/") + "/"
    return urljoin(base, endpoint.lstrip("/"))


@dataclass
class APIConfig:
    """Configuration for API client."""

    api_key: str
    api_server: Optional[str] = "https://api.greynoise.io"
    timeout: Optional[int] = 60
    proxy: Optional[str] = None
    offering: Optional[str] = "enterprise"
    integration_name: Optional[str] = None
    cache_max_size: Optional[int] = 1000000
    cache_ttl: Optional[int] = 3600
    use_cache: Optional[bool] = True
    psychic: Optional[bool] = False
    psychic_model: Optional[int] = 1
    psychic_cache_dir: Optional[str] = None
    psychic_max_age_hours: Optional[int] = 1


class BaseAPIClient:
    """Base class for API clients with common functionality."""

    def __init__(self, config: APIConfig):
        self.config = config
        self.session = self._setup_session()
        self._setup_cache()

    def close(self) -> None:
        """Close the HTTP session and release the connection pool.

        Parallel batch work (:meth:`_process_batch_parallel`) uses short-lived
        thread pools internally; this method tears down the long-lived
        :class:`requests.Session`. Safe to call multiple times.
        """
        self.session.close()

    def _setup_session(self) -> requests.Session:
        """Set up a session with retry logic and connection pooling.

        urllib3 retries transient **5xx** responses only. **429 Too Many Requests** is
        intentionally excluded.
        """
        session = requests.Session()

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[500, 502, 503, 504],
        )

        # Mount the adapter with retry strategy
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=10, pool_maxsize=10)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _setup_cache(self) -> None:
        """Initialize cache with configured parameters."""
        self.ip_quick_check_cache = initialize_cache(self.config.cache_max_size, self.config.cache_ttl)
        self.ip_context_cache = initialize_cache(self.config.cache_max_size, self.config.cache_ttl)

    def _request(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        method: str = "get",
        include_headers: bool = False,
        proxy: Optional[str] = None,
        extra_headers: Optional[Dict[str, Any]] = None,
    ) -> Union[Dict[str, Any], tuple, str]:
        """Handle API requests with proper error handling and logging.

        ``extra_headers`` are merged on top of the default ``User-Agent`` and
        ``key`` headers so callers (e.g. :meth:`GreyNoise.request`) can add or
        override values such as ``Accept`` without reimplementing auth.
        """
        if params is None:
            params = {}

        # Use config proxy when no proxy is explicitly passed
        proxy = proxy or self.config.proxy

        user_agent_parts = ["GreyNoise/{}".format(__version__)]
        if self.config.integration_name:
            user_agent_parts.append("({})".format(self.config.integration_name))

        req_headers = {
            "User-Agent": " ".join(user_agent_parts),
            "key": self.config.api_key,
        }
        if extra_headers:
            req_headers.update(extra_headers)

        url = _api_request_url(self.config.api_server, endpoint)

        # Avoid urlencode / large string work unless DEBUG is enabled (hot path).
        if LOGGER.isEnabledFor(logging.DEBUG):
            LOGGER.debug("Sending API request...URL: %s", url)
            LOGGER.debug("Sending API request...method: %s", method)
            LOGGER.debug("Sending API request...params: %s", params)
            LOGGER.debug("Sending API request...files: %s", files)
            LOGGER.debug("Sending API request...proxy: %s", proxy)
            if params:
                full_url = "{}?{}".format(url, urlencode(params))
            else:
                full_url = url
            LOGGER.debug("Full request URL with parameters: %s", full_url)

        request_method = getattr(self.session, method)
        try:
            if proxy:
                proxies = {protocol: proxy for protocol in ("http", "https")}
                response = request_method(
                    url,
                    headers=req_headers,
                    timeout=self.config.timeout,
                    params=params,
                    json=json,
                    files=files,
                    proxies=proxies,
                )
            else:
                response = request_method(
                    url,
                    headers=req_headers,
                    timeout=self.config.timeout,
                    params=params,
                    json=json,
                    files=files,
                )

            content_type = response.headers.get("Content-Type", "")
            resp_headers = response.headers

            if "application/json" in content_type:
                try:
                    body = response.json()
                except ValueError as exc:
                    # Includes json.JSONDecodeError (malformed body, truncated proxy HTML, etc.)
                    raw = response.text
                    preview = raw if len(raw) <= 500 else raw[:500] + "..."
                    LOGGER.error(
                        "Response Content-Type is JSON but body could not be decoded: %s",
                        exc,
                    )
                    raise RequestFailure(response.status_code, preview)
            else:
                body = response.text

            LOGGER.debug("API response received %s", response.status_code)

            if response.status_code == 429:
                raise RateLimitError()
            if response.status_code >= 400 and response.status_code != 404:
                raise RequestFailure(response.status_code, body)

            if include_headers:
                return body, resp_headers
            else:
                return body

        except requests.exceptions.RequestException as e:
            LOGGER.error("Request failed: %s", str(e))
            raise RequestFailure(0, str(e))

    def _process_batch_parallel(
        self,
        items: List[Any],
        process_func: Callable[[List[Any]], Union[List[Any], Dict[str, Any]]],
        batch_size: int = 1000,
        max_workers: int = 10,
    ) -> Union[List[Any], Dict[str, List[Any]]]:
        """
        Process items in parallel batches.

        Args:
            items: List of items to process
            process_func: Function to process each batch
            batch_size: Size of each batch
            max_workers: Maximum number of parallel workers

        Returns:
            Accumulated list or dict with values grouped by key.
        """
        chunks = more_itertools.chunked(items, batch_size)
        first_result_type = None
        list_results = []
        dict_results = defaultdict(list)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_chunk = {executor.submit(process_func, chunk): chunk for chunk in chunks}

            for future in as_completed(future_to_chunk):
                try:
                    chunk_results = future.result()

                    if first_result_type is None:
                        first_result_type = type(chunk_results)
                        if first_result_type not in [list, dict]:
                            raise TypeError("Unsupported result type: must be list or dict")

                    if isinstance(chunk_results, list):
                        list_results.extend(chunk_results)
                    elif isinstance(chunk_results, dict):
                        for key, value in chunk_results.items():
                            if isinstance(value, list):
                                dict_results[key].extend(value)
                            else:
                                dict_results[key].append(value)

                except Exception as e:
                    LOGGER.error("Error processing batch: %s", str(e))
                    raise

        return list_results if first_result_type is list else dict(dict_results)


def initialize_cache(cache_max_size, cache_ttl):
    """A function to initialize cache"""
    cache = cachetools.TTLCache(maxsize=cache_max_size, ttl=cache_ttl)
    return cache


class GreyNoise(BaseAPIClient):
    """GreyNoise API client.

    :param api_key: Key use to access the API.
    :type api_key: str
    :param timeout: API requests timeout in seconds.
    :type timeout: int
    :param proxy: Add URL for proxy to redirect lookups
    :type proxy: str

    """

    NAME = "GreyNoise"
    EP_GNQL = "v3/gnql"
    EP_GNQL_METADATA = "v3/gnql/metadata"
    EP_GNQL_STATS = "v3/gnql/stats"
    EP_IP = "v3/ip/{ip_address}"
    EP_NOISE_MULTI = "v3/ip?quick=true"
    EP_NOISE_CONTEXT_MULTI = "v3/ip"
    EP_TIMELINE_IP = "v3/noise/ips/{ip_address}/timeline"
    EP_TAGS = "v3/tags"
    EP_PING = "ping"
    EP_SENSOR_LIST = "v1/workspaces/{workspace_id}/sensors"
    EP_PERSONA_DETAILS = "v1/personas/{persona_id}"
    EP_CVE_LOOKUP = "v1/cve/{cve_id}"
    EP_CVES_BULK = "v3/cves"
    EP_ANALYZE_UPLOAD = "v2/analyze/upload"
    EP_ANALYZE = "v2/analyze/{id}"
    EP_RECALL = "v3/gnql/timeseries"
    EP_RECALL_STATS = "v3/gnql/timeseries/stats"
    EP_CALLBACK_IP = "v1/callback/ip/{ip_address}"
    EP_CALLBACK_LIST = "v1/callback/ips"
    EP_CALLBACK_EXPORT_IPS = "v1/callback/export-ips"
    EP_CALLBACK_OVERVIEW = "v1/callback/overview"
    EP_NOT_IMPLEMENTED = "v2/request/{subcommand}"
    UNKNOWN_CODE_MESSAGE = "Code message unknown: {}"

    IP_MULTI_CHECK_CHUNK_SIZE = 10000
    #: Max status polls after upload (inclusive of re-checking the upload response as poll 0).
    ANALYZE_MAX_POLL_ATTEMPTS = 360
    #: Seconds to wait between analyze job status polls.
    ANALYZE_POLL_INTERVAL_SECONDS = 5
    _ANALYZE_FAILED_STATES = frozenset(("failed", "error", "cancelled"))

    IPV4_REGEX = re.compile(r"(?:{octet}\.){{3}}{octet}".format(octet=r"(?:(?:25[0-5])|(?:2[0-4]\d)|(?:1?\d?\d))"))

    def __init__(self, config: APIConfig):
        super().__init__(config)
        self.offering = config.offering

        # Initialize Psychic if enabled
        self._psychic = None
        if config.psychic:
            from greynoise.psychic import Psychic

            if config.psychic_model:
                model = config.psychic_model
            else:
                model = 1

            self._psychic = Psychic(
                api_key=config.api_key,
                model=model,
                cache_dir=config.psychic_cache_dir,
                max_age_hours=config.psychic_max_age_hours,
                auto_download=True,
            )
            LOGGER.info("Psychic enabled")

    def _get_psychic_for_download(self, model: Optional[int] = None):
        """Return a Psychic client for download operations, creating one if needed."""
        from greynoise.psychic import Psychic

        requested_model = model if model is not None else (self.config.psychic_model or 1)

        if self._psychic is None:
            self._psychic = Psychic(
                api_key=self.config.api_key,
                model=requested_model,
                cache_dir=self.config.psychic_cache_dir,
                max_age_hours=self.config.psychic_max_age_hours,
                auto_download=False,
            )
        elif model is not None:
            self._psychic.model = requested_model

        return self._psychic

    def psychic_download(
        self,
        date: str,
        file_format: str,
        output_path: Optional[str] = None,
        model: Optional[int] = None,
    ) -> str:
        """
        Download a Psychic file and write it to disk.

        :param date: Date in YYYY-MM-DD format
        :param file_format: File format to download (``bin``, ``mmdb``, or ``csv``)
        :param output_path: Directory or file path for the download (default: current directory)
        :param model: Psychic model to use (1, 2, or 3; default: from config or 1)
        :return: Path to the written file
        :rtype: str
        """
        psychic = self._get_psychic_for_download(model)
        directory = output_path or "."

        if file_format == "bin":
            return psychic.download_bitmap(date, directory)
        if file_format == "mmdb":
            return psychic.download_mmdb(date, directory)
        if file_format == "csv":
            return psychic.download_csv(date, directory)

        raise ValueError("file_format must be 'bin', 'mmdb', or 'csv'")

    def psychic_generate(
        self,
        start_date: str,
        end_date: str,
        output_path: Optional[str] = None,
        model: Optional[int] = None,
    ) -> str:
        """
        Generate a Psychic bitmap for a date range and write it to disk.

        :param start_date: Start date in YYYY-MM-DD format
        :param end_date: End date in YYYY-MM-DD format
        :param output_path: Directory or file path for the generated file
            (default: current directory)
        :param model: Psychic model to use (1, 2, or 3; default: from config or 1)
        :return: Path to the written bitmap file
        :rtype: str
        """
        from pathlib import Path

        from greynoise.psychic import _psychic_output_path

        psychic = self._get_psychic_for_download(model)
        directory = output_path or "."
        file_path = _psychic_output_path(
            directory,
            Path("."),
            f"psychic_m{psychic.model}_{start_date}_{end_date}.bin",
        )
        bitmap_data = psychic._generate_bitmap(start_date, end_date)
        file_path.write_bytes(bitmap_data)
        return str(file_path)

    def request(
        self,
        endpoint: str,
        method: str = "get",
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        proxy: Optional[str] = None,
    ) -> Union[Dict[str, Any], str]:
        """Make a request to the GreyNoise API.

        Args:
            endpoint: API endpoint to request
            method: HTTP method to use
            params: URL parameters to include
            json: JSON data to include
            files: Files to include
            headers: Extra headers merged after defaults (``User-Agent``, ``key``).
                If omitted, ``Accept: application/json`` is set for typical API use.
            proxy: Proxy URL to use for the request

        Returns:
            Parsed JSON (dict), or raw response body (str) for non-JSON responses.
        """
        extra: Dict[str, Any] = {}
        if headers is not None:
            extra.update(headers)
        if "Accept" not in extra:
            extra["Accept"] = "application/json"
        return self._request(
            endpoint,
            method=method,
            params=params,
            json=json,
            files=files,
            extra_headers=extra,
            proxy=proxy,
        )

    def analyze(self, text):
        """Aggregate stats related to IP addresses from a given text.

        :param text: Text input
        :type text: file-like | str
        :return: Aggregated stats for all the IP addresses found.
        :rtype: dict

        """
        if self.offering == "community":
            text_stats = [{"message": "Analyze not supported with Community offering"}]
        else:
            text_stats = {
                "query": [],
                "count": 0,
                "stats": {},
            }

            files = {"file": text}
            upload = self._request(self.EP_ANALYZE_UPLOAD, files=files, method="post")

            if "uuid" not in upload:
                text_stats["message"] = upload.get(
                    "message",
                    "Analyze upload did not return a job identifier (uuid).",
                )
            else:
                job_id = upload["uuid"]
                response: Optional[Dict[str, Any]] = upload
                for poll in range(self.ANALYZE_MAX_POLL_ATTEMPTS + 1):
                    state = str(response.get("state", "")).lower()
                    if state == "completed":
                        break
                    if state in self._ANALYZE_FAILED_STATES:
                        text_stats["message"] = response.get(
                            "message",
                            "Analyze job failed with state {!r}.".format(response.get("state", "")),
                        )
                        response = None
                        break
                    if poll == self.ANALYZE_MAX_POLL_ATTEMPTS:
                        text_stats["message"] = (
                            "Analyze job did not reach a completed state after "
                            "{} status checks (last state {!r}).".format(
                                self.ANALYZE_MAX_POLL_ATTEMPTS,
                                response.get("state", ""),
                            )
                        )
                        response = None
                        break
                    time.sleep(self.ANALYZE_POLL_INTERVAL_SECONDS)
                    response = self._request(self.EP_ANALYZE.format(id=job_id))

                if response is not None:
                    details = response.get("details") or {}
                    unique_ip_list = (
                        details.get("noise_ips_found", [])
                        + details.get("unknown_ips", [])
                        + details.get("riot_ips_found", [])
                    )

                    text_stats["summary"] = {
                        "ip_count": details.get("unique_ips", 0),
                        "noise_ip_count": details.get("noise_ips", 0),
                        "not_noise_ip_count": details.get("non_noise_ips", 0),
                        "riot_ip_count": details.get("riot_ips", 0),
                        "noise_ip_ratio": details.get("percentage_of_noise_ips", 0),
                        "riot_ip_ratio": details.get("percentage_of_riot_ips", 0),
                    }
                    text_stats["stats"] = response.get("stats")
                    text_stats["query"] = unique_ip_list
                    text_stats["count"] = details.get("unique_ips", 0)

        return text_stats

    def filter(self, text, noise_only=False, riot_only=False):
        """Filter lines that contain IP addresses from a given text.

        :param text: Text input
        :type text: file-like | str
        :param noise_only:
            If set, return only lines that contain IP addresses classified as noise,
            otherwise, return lines that contain IP addresses not classified as noise.
        :type noise_only: bool
        :param riot_only:
            If set, return only lines that contain IP addresses in RIOT,
            otherwise, return lines that contain IP addresses not in RIOT.
        :type riot_only: bool
        :return: Iterator that yields lines in chunks
        :rtype: iterable

        """
        gnfilter = Filter(self)
        for filtered_chunk in gnfilter.filter(text, noise_only=noise_only, riot_only=riot_only):
            yield filtered_chunk

    @staticmethod
    def _ip_lookup_response_cacheable(response: Any) -> bool:
        """Whether a raw IP lookup JSON body should be stored in ``ip_context_cache``.

        Error and not-found payloads (for example HTTP 404 bodies) often carry a
        top-level ``message`` and should not be cached: the address might later
        appear in the dataset and a stale cached error would hide fresh data.
        """
        if not isinstance(response, dict):
            return False
        if response.get("message"):
            return False
        return True

    @staticmethod
    def _coerce_bulk_ip_post_response(api_result: Any) -> Dict[str, List[Any]]:
        """Normalize POST ``/v3/ip`` (multi / quick) JSON for batch merging.

        Ensures each worker returns a dict whose values are lists so
        :meth:`_process_batch_parallel` can merge chunks without corrupting
        results when the API returns an error object, wrong types, or omits keys.
        """
        if not isinstance(api_result, dict):
            LOGGER.error(
                "Bulk IP lookup returned %s instead of a dict; treating as empty.",
                type(api_result).__name__,
            )
            return {"data": [], "request_metadata": []}

        data = api_result.get("data")
        if not isinstance(data, list):
            if data is not None:
                LOGGER.error(
                    "Bulk IP lookup 'data' must be a list, not %s",
                    type(data).__name__,
                )
            data = []

        meta = api_result.get("request_metadata")
        if isinstance(meta, dict):
            meta = [meta]
        elif not isinstance(meta, list):
            if meta is not None:
                LOGGER.error(
                    "Bulk IP lookup 'request_metadata' must be a list, not %s",
                    type(meta).__name__,
                )
            meta = []

        return {"data": data, "request_metadata": meta}

    def ip(self, ip_address):  # pylint: disable=C0103
        """Get context associated with an IP address.

        :param ip_address: IP address to use in the look-up.
        :type ip_address: str
        :return: Context for the IP address.
        :rtype: dict

        When caching is enabled, successful-looking responses are cached;
        error-shaped bodies (typically with a ``message`` field) are not.

        """
        LOGGER.debug("Getting context for %s...", ip_address)
        validate_ip(ip_address)

        endpoint = self.EP_IP.format(ip_address=ip_address)

        if self.config.use_cache:
            cache = self.ip_context_cache
            if ip_address in cache:
                response = cache[ip_address]
            else:
                response = self._request(endpoint)
                if self._ip_lookup_response_cacheable(response):
                    cache[ip_address] = response
        else:
            response = self._request(endpoint)
        if "ip" not in response:
            response["ip"] = ip_address
            response["business_service_intelligence"] = {"found": False}
            response["internet_scanner_intelligence"] = {"found": False}

        return response

    def not_implemented(self, subcommand_name):
        """Send request for a not implemented CLI subcommand.

        :param subcommand_name: Name of the CLI subcommand
        :type subcommand_name: str

        """
        endpoint = self.EP_NOT_IMPLEMENTED.format(subcommand=subcommand_name)
        response = self._request(endpoint)
        return response

    def query(
        self,
        query,
        size=None,
        scroll=None,
        exclude_raw=False,
        quick=False,
        exclude_fields: Optional[Union[str, List[str]]] = None,
    ) -> Dict[str, Any]:
        """Run GNQL query.

        :param query: GNQL query
        :type query: str
        :param size: Max number of results to return
        :type size: int
        :param scroll: Scroll token for pagination
        :type scroll: str
        :param exclude_raw: Whether to exclude raw results
        :type exclude_raw: bool
        :param quick: Whether to use quick lookup
        :type quick: bool
        :param exclude_fields: Field names to exclude; comma-separated string or list
            of strings (sent to the API as the ``exclude`` query parameter).
        :type exclude_fields: str or list[str]
        """
        if self.offering == "community":
            response = {"message": "GNQL not supported with Community offering"}
        else:
            LOGGER.debug(
                "Running GNQL query: %s %s %s %s %s...",
                query,
                size,
                scroll,
                quick,
                exclude_fields,
            )
            params = {"query": query, "quick": quick}
            if size is not None:
                params["size"] = size
            if scroll is not None:
                params["scroll"] = scroll
            if exclude_fields is not None:
                if isinstance(exclude_fields, str):
                    normalized_ef = ",".join(p.strip() for p in exclude_fields.split(",") if p.strip())
                else:
                    normalized_ef = ",".join(str(p).strip() for p in exclude_fields if str(p).strip())
                if normalized_ef:
                    params["exclude"] = normalized_ef
            if exclude_raw:
                LOGGER.debug("Using GNQL Metadata endpoint")
                endpoint = self.EP_GNQL_METADATA
            else:
                LOGGER.debug("Using GNQL Full endpoint")
                endpoint = self.EP_GNQL
            response = self._request(endpoint, params=params)

        return response

    def quick(
        self,
        ip_addresses: Union[str, List[str]],
        include_invalid: bool = False,
    ) -> List[Dict[str, Any]]:
        """Get activity associated with one or more IP addresses.

        Args:
            ip_addresses: One or more IP addresses to look up
            include_invalid: Whether to include invalid IPs in results

        Returns:
            List of results for each IP address
        """
        if self.offering == "community":
            return [{"message": "Quick Lookup not supported with Community offering"}]

        if isinstance(ip_addresses, str):
            ip_addresses = ip_addresses.split(",")

        LOGGER.debug("Getting noise status for %s IPs...", len(ip_addresses))

        valid_ip_addresses = [
            ip_address for ip_address in ip_addresses if validate_ip(ip_address, strict=False, print_warning=False)
        ]

        def process_chunk(chunk: List[str]) -> Dict[str, List[Any]]:
            """Process a chunk of IP addresses."""
            api_result = self._request(self.EP_NOISE_MULTI, method="post", json={"ips": chunk})
            return self._coerce_bulk_ip_post_response(api_result)

        # Process valid IPs in parallel batches
        if self.config.use_cache:
            # Keep the same ordering as in the input
            LOGGER.debug("Using cache for quick lookup")
            ordered_results = OrderedDict(
                (ip_address, self.ip_quick_check_cache.get(ip_address)) for ip_address in valid_ip_addresses
            )
            api_ip_addresses = [ip_address for ip_address, result in ordered_results.items() if result is None]

        else:
            LOGGER.debug("Not using cache for quick lookup")
            # Keep the same ordering as in the input
            ordered_results = OrderedDict((ip_address, None) for ip_address in valid_ip_addresses)
            api_ip_addresses = [ip_address for ip_address, result in ordered_results.items() if result is None]
        if api_ip_addresses:
            api_results = self._process_batch_parallel(
                api_ip_addresses,
                process_chunk,
                batch_size=self.IP_MULTI_CHECK_CHUNK_SIZE,
            )

            ip_results = []
            ips_not_found = []
            for key, values in api_results.items():
                if key == "data":
                    ip_results = values
                if key == "request_metadata":
                    for item in values:
                        if not isinstance(item, dict):
                            LOGGER.warning("Skipping non-dict request_metadata entry: %r", item)
                            continue
                        ips_not_found.extend(item.get("ips_not_found") or [])

            for result in ip_results:
                if not isinstance(result, dict) or "ip" not in result:
                    LOGGER.warning("Skipping bulk quick row without dict or 'ip' key: %r", result)
                    continue
                ip_address = result["ip"]
                ordered_results[ip_address] = result
                if self.config.use_cache:
                    self.ip_quick_check_cache[ip_address] = result

            for item in ips_not_found:
                result = {
                    "ip": item,
                    "business_service_intelligence": {
                        "found": False,
                        "trust_level": "",
                    },
                    "internet_scanner_intelligence": {
                        "found": False,
                        "classification": "",
                    },
                }
                ordered_results[item] = result
                if self.config.use_cache:
                    self.ip_quick_check_cache[item] = result

        if include_invalid:
            for ip_address in ip_addresses:
                if ip_address not in valid_ip_addresses:
                    ordered_results[ip_address] = {
                        "ip": ip_address,
                        "business_service_intelligence": {
                            "found": False,
                            "trust_level": "",
                        },
                        "internet_scanner_intelligence": {
                            "found": False,
                            "classification": "",
                        },
                    }

        results = [result for result in ordered_results.values() if result is not None]

        return results

    def ip_multi(self, ip_addresses, include_invalid=False):  # pylint: disable=R0912
        """Get activity associated with one or more IP addresses.

        :param ip_addresses: One or more IP addresses to use in the look-up.
        :type ip_addresses: str | list
        :return: Bulk status information for IP addresses.
        :rtype: dict

        :param include_invalid: True or False
        :type include_invalid: bool

        """

        def process_chunk(chunk: List[str]) -> Dict[str, List[Any]]:
            """Process a chunk of IP addresses."""
            api_result = self._request(self.EP_NOISE_CONTEXT_MULTI, method="post", json={"ips": chunk})
            return self._coerce_bulk_ip_post_response(api_result)

        if self.offering == "community":  # pylint: disable=R1702
            results = [{"message": "IP Multi Lookup not supported with Community offering"}]
        else:
            if isinstance(ip_addresses, str):
                ip_addresses = ip_addresses.split(",")

            LOGGER.debug("Getting noise context for %s IPs...", len(ip_addresses))

            valid_ip_addresses = [
                ip_address for ip_address in ip_addresses if validate_ip(ip_address, strict=False, print_warning=False)
            ]

            # Process valid IPs in parallel batches
            if self.config.use_cache:
                # Keep the same ordering as in the input
                LOGGER.debug("Using cache for ip_multi lookup")
                ordered_results = OrderedDict(
                    (ip_address, self.ip_context_cache.get(ip_address)) for ip_address in valid_ip_addresses
                )
                api_ip_addresses = [ip_address for ip_address, result in ordered_results.items() if result is None]

            else:
                LOGGER.debug("Not using cache for ip_multi lookup")
                # Keep the same ordering as in the input
                ordered_results = OrderedDict((ip_address, None) for ip_address in valid_ip_addresses)
                api_ip_addresses = [ip_address for ip_address, result in ordered_results.items() if result is None]
            if api_ip_addresses:
                api_results = self._process_batch_parallel(
                    api_ip_addresses,
                    process_chunk,
                    batch_size=self.IP_MULTI_CHECK_CHUNK_SIZE,
                )

                ip_results = []
                ips_not_found = []
                for key, values in api_results.items():
                    if key == "data":
                        ip_results = values
                    if key == "request_metadata":
                        for item in values:
                            if not isinstance(item, dict):
                                LOGGER.warning(
                                    "Skipping non-dict request_metadata entry: %r",
                                    item,
                                )
                                continue
                            ips_not_found.extend(item.get("ips_not_found") or [])

                for result in ip_results:
                    if not isinstance(result, dict) or "ip" not in result:
                        LOGGER.warning(
                            "Skipping bulk ip_multi row without dict or 'ip' key: %r",
                            result,
                        )
                        continue
                    ip_address = result["ip"]
                    ordered_results[ip_address] = result

                for item in ips_not_found:
                    ordered_results[item] = {
                        "ip": item,
                        "business_service_intelligence": {
                            "found": False,
                            "trust_level": "",
                        },
                        "internet_scanner_intelligence": {
                            "found": False,
                            "classification": "",
                        },
                    }

            if include_invalid:
                for ip_address in ip_addresses:
                    if ip_address not in valid_ip_addresses:
                        ordered_results[ip_address] = {
                            "ip": ip_address,
                            "business_service_intelligence": {
                                "found": False,
                                "trust_level": "",
                            },
                            "internet_scanner_intelligence": {
                                "found": False,
                                "classification": "",
                            },
                        }

            results = [result for result in ordered_results.values() if result is not None]

            return results

    def stats(self, query, count=None):
        """Run GNQL stats query."""
        if self.offering == "community":
            response = {"message": "Stats Query not supported with Community offering"}
        else:
            LOGGER.debug("Running GNQL stats query: %s...", query)
            params = {"query": query}
            if count is not None:
                params["count"] = count
            response = self._request(self.EP_GNQL_STATS, params=params)

        return response

    def tags(
        self,
        name: Optional[str] = None,
        slug: Optional[str] = None,
        cve: Optional[str] = None,
    ) -> Dict[str, Any]:
        """List tags and tag metadata (``GET /v3/tags``).

        Optional query filters match the API: partial ``name``, exact ``slug``,
        and ``cve`` (CVE ID associated with a tag).

        :param name: Filter by tag name (partial match).
        :param slug: Filter by slug (exact match).
        :param cve: Filter by associated CVE ID.
        :return: API JSON body, or a dict with ``message`` for Community offering.
        """
        if self.offering == "community":
            return {"message": "Tags lookup is not supported with Community offering"}

        params: Dict[str, Any] = {}
        if name is not None:
            params["name"] = name
        if slug is not None:
            params["slug"] = slug
        if cve is not None:
            validate_cve_id(cve)
            params["cve"] = cve

        LOGGER.debug("Getting tags (filters: %s)...", params or "none")
        return self._request(self.EP_TAGS, params=params)

    def metadata(self):
        """Get tag metadata (same as :meth:`tags` with no filters).

        Retained for backwards compatibility; calls :meth:`tags` unfiltered.
        """
        return self.tags()

    def test_connection(self):
        """Test the API connection and API key."""
        LOGGER.debug("Testing access to GreyNoise API and for valid API Key")
        response = self._request(self.EP_PING)
        return response

    def riot(self, ip_address):
        """Check if IP is in RIOT data set

        :param ip_address: IP address to use in the look-up.
        :type ip_address: str
        :return: Context for the IP address.
        :rtype: dict

        """
        LOGGER.warning(
            "The riot() function is deprecated and will be removed in" " a future version. Please use ip() instead."
        )
        return self.ip(ip_address)

    def sensor_activity(
        self,
        workspace_id,
        file_format=None,
        start_time=None,
        end_time=None,
        persona_id=None,
        source_ip=None,
        size=None,
        scroll=None,
        include_headers=False,
    ):
        """Get session data from sensors"""
        LOGGER.warning("The sensor_activity() function is deprecated and will be removed in" " a future version.")
        return False, "Function deprecated"

    def sensor_activity_ips(
        self,
        workspace_id,
        file_format=None,
        start_time=None,
        end_time=None,
        persona_id=None,
        source_ip=None,
        size=None,
        scroll=None,
    ):
        """Collect distinct ``source_ip`` values from sensor activity rows."""
        LOGGER.warning("The sensor_activity_ips() function is deprecated and will be removed in" " a future version.")
        return False, "Function deprecated"

    def similar(self, ip_address, limit=None, min_score=None):
        """Query IP on the IP Similarity API

        :param ip_address: IP address to use in the look-up.
        :type ip_address: str
        :param limit: Limit the number of matches returned by the endpoint
        :type limit: str
        :param limit: Limit the number of matches returned by the endpoint
        :type limit: str
        :return: Context for the IP address.
        :rtype: dict


        """
        LOGGER.warning("The similar() function is deprecated and will be removed in" " a future version.")
        return False, "Function deprecated"

    def timeline(self, ip_address, field="classification", days=None, granularity=None):
        """Query IP on the IP TimeSeries API

        :param ip_address: IP address to use in the look-up.
        :type ip_address: str
        :param field: field name to use to retrieve timeline information
        :type field: str
        :param days: Number of days to show data for
        :type days: int
        :param granularity: Granularity of activity date ranges
        :type granularity: str
        :return: Context for the IP address.
        :rtype: dict


        """
        if self.offering == "community":
            response = {"message": "Timeline lookup not supported with Community offering"}
        else:
            LOGGER.debug("Checking IP Timeline results for %s...", ip_address)
            validate_ip(ip_address)
            if not field:
                field = "classification"
            validate_timeline_field_value(field)
            if days:
                validate_timeline_days(days)
            if granularity:
                validate_timeline_granularity(granularity)

            endpoint = self.EP_TIMELINE_IP.format(ip_address=ip_address)
            endpoint = endpoint + f"?field={field.lower()}"
            if days:
                endpoint = endpoint + f"&days={days}"
            if granularity:
                endpoint = endpoint + f"&granularity={granularity}"
            response = self._request(endpoint)

            if "ip" not in response:
                response["ip"] = ip_address

        return response

    def timelinehourly(self, ip_address, days=None, cursor=None, limit=100):
        """Query IP on the IP TimeSeries API

        :param ip_address: IP address to use in the look-up.
        :type ip_address: str
        :param cursor:
            The cursor is a pointer from which to start returning
            results up to the limit
        :type cursor: str
        :param days: Number of days to show data for
        :type days: int
        :param limit: The total number of events to return in the response
        :type limit: str
        :return: Context for the IP address.
        :rtype: dict


        """
        LOGGER.warning("The timelinehourly() function is deprecated and will be removed in" " a future version.")
        return False, "Function deprecated"

    def timelinedaily(self, ip_address, days=30):
        """Query IP on the IP TimeSeries API

        :param ip_address: IP address to use in the look-up.
        :type ip_address: str
        :param cursor:
            The cursor is a pointer from which to start returning
            results up to the limit
        :type cursor: str
        :param days: Number of days to show data for
        :type days: int
        :param limit: The total number of events to return in the response
        :type limit: str
        :return: Context for the IP address.
        :rtype: dict


        """
        if self.offering == "community":
            response = {"message": "Timeline lookup not supported with Community offering"}
        else:
            LOGGER.debug("Checking IP Timeline results for %s...", ip_address)
            validate_ip(ip_address)
            if days:
                validate_timeline_days(days)

            user_agent_parts = ["greynoise-sdk-timeline-function/1.0"]
            if self.config.integration_name:
                user_agent_parts.append("({})".format(self.config.integration_name))
            user_agent = " ".join(user_agent_parts)

            response = get_greynoise_timeline(
                ip=ip_address,
                api_key=self.config.api_key,
                days=days,
                granularity="1d",
                max_workers=4,
                user_agent=user_agent,
            )

        return response

    def sensor_list(self, workspace_id=None):
        """Get list of current sensors for Workspace

        :param workspace_id: ID of Workspace
        :type workspace_id: str


        """
        if self.offering == "community":
            response = {"message": "Sensors List is not supported with Community offering"}
        else:
            LOGGER.debug("Getting Sensor List for Workspace ID: %s...", workspace_id)

            endpoint = self.EP_SENSOR_LIST.format(workspace_id=workspace_id)
            response = self._request(endpoint)
        new_response = {}
        if "items" in response:
            new_response["items"] = []
            for sensor in response["items"]:
                persona = self.persona_details(sensor["persona"])
                sensor["persona_name"] = persona.get("name", "")
                new_response["items"].append(sensor)
        else:
            new_response = response

        return new_response

    def persona_details(self, persona_id=None):
        """Get persona details by ID

        :param persona_id: ID of Persona
        :type persona_id: str


        """
        if self.offering == "community":
            response = {"message": "Persona Details is not supported with Community offering"}
        else:
            LOGGER.debug("Getting Persona Details for Workspace ID: %s...", persona_id)

            endpoint = self.EP_PERSONA_DETAILS.format(persona_id=persona_id)
            response = self._request(endpoint)

        return response

    def cve(self, cve_id=None):
        """Get CVE details by CVE ID

        :param cve_id: ID of CVE
        :type cve_id: str


        """
        if self.offering == "community":
            response = {"message": "CVE lookup is not supported with Community offering"}
        else:
            LOGGER.debug("Getting Details for CVE ID: %s...", cve_id)

            # check if CVE submitted is in correct format
            validate_cve_id(cve_id)

            endpoint = self.EP_CVE_LOOKUP.format(cve_id=cve_id)
            response = self._request(endpoint)

        return response

    def cves(self, cve_ids: List[str]) -> Union[List[Dict[str, Any]], Dict[str, Any]]:
        """Look up multiple CVEs in a single request.

        Up to 10,000 CVE IDs per call.

        :param cve_ids: CVE identifiers (e.g. ``CVE-2021-44228``).
        :type cve_ids: list[str]
        :return: API response: list of CVE records, or a dict with an error ``message``
            when using the Community offering.
        :rtype: list[dict] | dict
        """
        if self.offering == "community":
            return {"message": "Bulk CVE lookup is not supported with Community offering"}

        if not cve_ids:
            raise ValueError("At least one CVE ID is required")
        if len(cve_ids) > 10000:
            raise ValueError("Maximum number of CVEs per request is 10000")

        for cve_id in cve_ids:
            validate_cve_id(cve_id)

        LOGGER.debug("Bulk CVE lookup for %s IDs...", len(cve_ids))
        return self._request(self.EP_CVES_BULK, method="post", json={"cves": cve_ids})

    def psychic_lookup(self, ip_address: str) -> Dict[str, Any]:
        """
        Look up an IP address using Psychic offline bitmaps.

        :param ip_address: IP address to look up
        :type ip_address: str
        :return: Dictionary with IP information from Psychic bitmap
        :rtype: dict
        :raises: RuntimeError if psychic is not enabled
        """
        if not self._psychic:
            raise RuntimeError(
                "Psychic is not enabled. Initialize GreyNoise with psychic=True in config "
                "or GREYNOISE_PSYCHIC environment variable"
            )

        return self._psychic.lookup_ip(ip_address)

    def psychic_lookup_ips(self, ips: List[str]) -> List[Dict[str, Any]]:
        """
        Look up multiple IP addresses using Psychic offline bitmaps.

        :param ips: List of IP addresses to look up
        :type ips: List[str]
        :return: List of dictionaries with IP information from Psychic bitmap
        :rtype: List[dict]
        :raises: RuntimeError if psychic is not enabled
        """
        if not self._psychic:
            raise RuntimeError(
                "Psychic is not enabled. Initialize GreyNoise with psychic=True in config "
                "or GREYNOISE_PSYCHIC environment variable"
            )

        return self._psychic.lookup_ips(ips)

    def psychic_stats(self) -> Dict[str, Any]:
        """
        Get statistics about the loaded Psychic bitmap.

        :return: Dictionary with bitmap statistics
        :rtype: dict
        :raises: RuntimeError if psychic is not enabled
        """
        if not self._psychic:
            raise RuntimeError(
                "Psychic is not enabled. Initialize GreyNoise with psychic=True in config "
                "or GREYNOISE_PSYCHIC environment variable"
            )

        return self._psychic.get_stats()

    def psychic_download_mmdb(self, date: str, output_path: Optional[str] = None) -> str:
        """
        Download mmdb for a specific date and write it to disk.

        :param date: Date to download mmdb for
        :type date: str
        :param output_path: Directory to write the MMDB file (default: current directory)
        :type output_path: str
        :return: Path to the written MMDB file
        :rtype: str
        """
        return self.psychic_download(date, "mmdb", output_path)

    def psychic_download_csv(self, date: str, output_path: Optional[str] = None) -> str:
        """
        Download psychic MMDB data for a date and export it to CSV.

        :param date: Date to download data for
        :type date: str
        :param output_path: Directory or file path for the CSV (default: current directory)
        :type output_path: str
        :return: Path to the written CSV file
        :rtype: str
        """
        return self.psychic_download(date, "csv", output_path)

    def psychic_download_bitmap(self, date: str, output_path: Optional[str] = None) -> str:
        """
        Download bitmap for a specific date and write it to disk.

        :param date: Date to download bitmap for
        :type date: str
        :param output_path: Directory to write the bitmap file (default: current directory)
        :type output_path: str
        :return: Path to the written bitmap file
        :rtype: str
        """
        return self.psychic_download(date, "bin", output_path)

    def psychic_generate_bitmap(self, start_date: str, end_date: str) -> bytes:
        """
        Generate bitmap for a date range.

        :param start_date: Start date to generate bitmap for
        :type start_date: str
        :param end_date: End date to generate bitmap for
        :type end_date: str
        :return: Bytes of the bitmap file
        :rtype: bytes
        """
        psychic = self._get_psychic_for_download()
        return psychic._generate_bitmap(start_date, end_date)

    def psychic_reload(self) -> None:
        """
        Force reload of Psychic bitmap data.

        :raises: RuntimeError if psychic is not enabled
        """
        if not self._psychic:
            raise RuntimeError(
                "Psychic is not enabled. Initialize GreyNoise with psychic=True in config "
                "or GREYNOISE_PSYCHIC environment variable"
            )

        self._psychic.reload()

    @property
    def psychic_enabled(self) -> bool:
        """Check if Psychic is enabled."""
        return self._psychic is not None

    @property
    def psychic(self):
        """Get direct access to the Psychic instance."""
        if not self._psychic:
            raise RuntimeError(
                "Psychic is not enabled. Initialize GreyNoise with psychic=True in config "
                "or GREYNOISE_PSYCHIC environment variable"
            )
        return self._psychic

    def recall(self, query=None, start=None, end=None, format="json", limit=None, offset=None):
        """Get Recall data for a given query

        :param query: Query to use in the look-up.
        :type query: str
        :param start: Start of the time range (RFC 3339 after normalization).
        :type start: str or datetime or None
        :param end: End of the time range (RFC 3339 after normalization).
        :type end: str or datetime or None
        :param format: Format to return the data in.
        :type format: str
        :param limit: Limit the number of results returned.
        :type limit: int
        :param offset: Offset the results returned.

        """
        if not query:
            raise ValueError("Query is required")

        if self.offering == "community":
            response = {"message": "Recall lookup is not supported with Community offering"}
        else:
            LOGGER.debug("Getting Recall data for query: %s...", query)
            start_norm = normalize_rfc3339_datetime(start)
            end_norm = normalize_rfc3339_datetime(end)
            params: Dict[str, Any] = {"query": query, "format": format}
            if start_norm is not None:
                params["start"] = start_norm
            if end_norm is not None:
                params["end"] = end_norm
            if limit is not None:
                params["limit"] = limit
            if offset is not None:
                params["offset"] = offset

            endpoint = self.EP_RECALL
            response = self._request(endpoint, params=params)

        return response

    def recall_stats(self, query=None, start=None, end=None, format="json", interval="hour"):
        """Get Recall data for a given query

        :param query: Query to use in the look-up.
        :type query: str
        :param interval: Interval to group the data by.
        :type interval: str

        """
        if not query:
            raise ValueError("Query is required")

        if self.offering == "community":
            response = {"message": "Recall lookup is not supported with Community offering"}
        else:
            LOGGER.debug("Getting Recall data for query: %s...", query)
            start_norm = normalize_rfc3339_datetime(start)
            end_norm = normalize_rfc3339_datetime(end)
            params: Dict[str, Any] = {"query": query, "format": format}
            if start_norm is not None:
                params["start"] = start_norm
            if end_norm is not None:
                params["end"] = end_norm
            if interval is not None:
                params["interval"] = interval

            endpoint = self.EP_RECALL_STATS
            response = self._request(endpoint, params=params)

        return response

    def callback_ip(self, ip_address=None, source_workspace="all"):
        """Get Recall data for a given query

        :param ip_address: IP address to use in the look-up.
        :type ip_address: str
        :param source_workspace: Source workspace to use in the look-up.
        :type source_workspace: str
        """

        if self.offering == "community":
            response = {"message": "Recall lookup is not supported with Community offering"}
        else:
            LOGGER.debug("Getting Callback data for IP: %s...", ip_address)
            source_workspace = source_workspace.lower()
            endpoint = self.EP_CALLBACK_IP.format(ip_address=ip_address)
            response = self._request(endpoint)

            if source_workspace != "all" and "source_workspaces" in response:
                workspaces_lower = {str(w).lower() for w in response["source_workspaces"]}
                if source_workspace not in workspaces_lower:
                    response = {"message": "IP not found in source workspace %s" % source_workspace}

        return response

    @staticmethod
    def _callback_filter_payload(
        *,
        is_stage_1: Optional[bool] = None,
        is_stage_2: Optional[bool] = None,
        first_seen_after: Optional[str] = None,
        first_seen_before: Optional[str] = None,
        last_seen_after: Optional[str] = None,
        last_seen_before: Optional[str] = None,
        has_files: Optional[bool] = None,
        file_type: Optional[str] = None,
        file_name: Optional[str] = None,
        file_hash: Optional[str] = None,
        scanner_ips: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Build JSON body fields shared by callback list and export endpoints."""
        return {
            k: v
            for k, v in (
                ("is_stage_1", is_stage_1),
                ("is_stage_2", is_stage_2),
                ("first_seen_after", first_seen_after),
                ("first_seen_before", first_seen_before),
                ("last_seen_after", last_seen_after),
                ("last_seen_before", last_seen_before),
                ("has_files", has_files),
                ("file_type", file_type),
                ("file_name", file_name),
                ("file_hash", file_hash),
                ("scanner_ips", scanner_ips),
                ("ips", ips),
            )
            if v is not None
        }

    def callback_list(
        self,
        *,
        is_stage_1: Optional[bool] = None,
        is_stage_2: Optional[bool] = None,
        first_seen_after: Optional[str] = None,
        first_seen_before: Optional[str] = None,
        last_seen_after: Optional[str] = None,
        last_seen_before: Optional[str] = None,
        has_files: Optional[bool] = None,
        file_type: Optional[str] = None,
        file_name: Optional[str] = None,
        file_hash: Optional[str] = None,
        scanner_ips: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
        page: Optional[int] = None,
        page_size: Optional[int] = None,
    ):
        """List callback IPs (paginated).

        :param is_stage_1: If true, only IPs where a file was downloaded (stage 1).
        :param is_stage_2: If true, only IPs suspected C2 from VT/sandbox (stage 2).
        :param first_seen_after: Only IPs first seen after this date (``YYYY-MM-DD``).
        :param first_seen_before: Only IPs first seen before this date (``YYYY-MM-DD``).
        :param last_seen_after: Only IPs last seen after this date (``YYYY-MM-DD``).
        :param last_seen_before: Only IPs last seen before this date (``YYYY-MM-DD``).
        :param has_files: If true, only IPs with malware files; if false, only without.
        :param file_type: Filter by MIME type (e.g. ``application/x-executable``).
        :param file_name: Filter by file name substring.
        :param file_hash: Filter by file SHA256 hash.
        :param scanner_ips: Only IPs associated with these scanner IPs.
        :param ips: Restrict to this set of callback IPs.
        :param page: Zero-indexed page (default on API: 0).
        :param page_size: Results per page, 1–100 (default on API: 20).

        """
        if self.offering == "community":
            response = {"message": "Callback list is not supported with Community offering"}
        else:
            LOGGER.debug("Getting Callback list...")
            payload = self._callback_filter_payload(
                is_stage_1=is_stage_1,
                is_stage_2=is_stage_2,
                first_seen_after=first_seen_after,
                first_seen_before=first_seen_before,
                last_seen_after=last_seen_after,
                last_seen_before=last_seen_before,
                has_files=has_files,
                file_type=file_type,
                file_name=file_name,
                file_hash=file_hash,
                scanner_ips=scanner_ips,
                ips=ips,
            )
            if page is not None:
                payload["page"] = page
            if page_size is not None:
                payload["page_size"] = page_size
            endpoint = self.EP_CALLBACK_LIST
            response = self._request(endpoint, method="post", json=payload or {})
        return response

    def callback_export_ips(
        self,
        *,
        is_stage_1: Optional[bool] = None,
        is_stage_2: Optional[bool] = None,
        first_seen_after: Optional[str] = None,
        first_seen_before: Optional[str] = None,
        last_seen_after: Optional[str] = None,
        last_seen_before: Optional[str] = None,
        has_files: Optional[bool] = None,
        file_type: Optional[str] = None,
        file_name: Optional[str] = None,
        file_hash: Optional[str] = None,
        scanner_ips: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
    ) -> Union[str, Dict[str, Any]]:
        """Export callback IPs as newline-delimited text (``POST .../export-ips``).

        Accepts the same filter fields as :meth:`callback_list` (not pagination).
        On success the API returns ``text/plain``; the client returns that body
        as a string (one IP per line).

        :rtype: str | dict
        """
        if self.offering == "community":
            return {"message": "Callback IP export is not supported with Community offering"}

        LOGGER.debug("Exporting Callback IPs...")
        payload = self._callback_filter_payload(
            is_stage_1=is_stage_1,
            is_stage_2=is_stage_2,
            first_seen_after=first_seen_after,
            first_seen_before=first_seen_before,
            last_seen_after=last_seen_after,
            last_seen_before=last_seen_before,
            has_files=has_files,
            file_type=file_type,
            file_name=file_name,
            file_hash=file_hash,
            scanner_ips=scanner_ips,
            ips=ips,
        )
        return self._request(self.EP_CALLBACK_EXPORT_IPS, method="post", json=payload or {})

    def callback_overview(
        self,
        *,
        is_stage_1: Optional[bool] = None,
        is_stage_2: Optional[bool] = None,
        first_seen_after: Optional[str] = None,
        first_seen_before: Optional[str] = None,
        last_seen_after: Optional[str] = None,
        last_seen_before: Optional[str] = None,
        has_files: Optional[bool] = None,
        file_type: Optional[str] = None,
        file_name: Optional[str] = None,
        file_hash: Optional[str] = None,
        scanner_ips: Optional[List[str]] = None,
        ips: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Callback IP aggregate statistics (``POST .../overview``).

        Same optional filters as :meth:`callback_export_ips` and :meth:`callback_list`
        (excluding pagination). Returns JSON (counts by stage, scanners, etc.).
        """
        if self.offering == "community":
            return {"message": "Callback overview is not supported with Community offering"}

        LOGGER.debug("Getting Callback overview...")
        payload = self._callback_filter_payload(
            is_stage_1=is_stage_1,
            is_stage_2=is_stage_2,
            first_seen_after=first_seen_after,
            first_seen_before=first_seen_before,
            last_seen_after=last_seen_after,
            last_seen_before=last_seen_before,
            has_files=has_files,
            file_type=file_type,
            file_name=file_name,
            file_hash=file_hash,
            scanner_ips=scanner_ips,
            ips=ips,
        )
        return self._request(self.EP_CALLBACK_OVERVIEW, method="post", json=payload or {})
