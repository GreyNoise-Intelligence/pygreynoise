"""GreyNoise API client."""

import logging
import re
import sys
import time
from collections import OrderedDict, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Union
from urllib.parse import urlencode

import cachetools
import more_itertools
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from greynoise.__version__ import __version__
from greynoise.api.filter import Filter
from greynoise.exceptions import RateLimitError, RequestFailure
from greynoise.util import (
    validate_cve_id,
    validate_ip,
    validate_similar_min_score,
    validate_timeline_days,
    validate_timeline_field_value,
    validate_timeline_granularity,
)

LOGGER = logging.getLogger(__name__)


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


class BaseAPIClient:
    """Base class for API clients with common functionality."""

    def __init__(self, config: APIConfig):
        self.config = config
        self.session = self._setup_session()
        self._setup_cache()
        self._executor = ThreadPoolExecutor(max_workers=10)

    def _setup_session(self) -> requests.Session:
        """Set up a session with retry logic and connection pooling."""
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=3,  # number of retries
            backoff_factor=1,  # wait 1, 2, 4 seconds between retries
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes to retry on
        )

        # Mount the adapter with retry strategy
        adapter = HTTPAdapter(
            max_retries=retry_strategy, pool_connections=10, pool_maxsize=10
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _setup_cache(self) -> None:
        """Initialize cache with configured parameters."""
        self.ip_quick_check_cache = initialize_cache(
            self.config.cache_max_size, self.config.cache_ttl
        )
        self.ip_context_cache = initialize_cache(
            self.config.cache_max_size, self.config.cache_ttl
        )

    def _request(
        self,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        method: str = "get",
        include_headers: bool = False,
        proxy: Optional[str] = None,
    ) -> Union[Dict[str, Any], tuple]:
        """Handle API requests with proper error handling and logging."""
        if params is None:
            params = {}

        user_agent_parts = ["GreyNoise/{}".format(__version__)]
        if self.config.integration_name:
            user_agent_parts.append("({})".format(self.config.integration_name))

        headers = {
            "User-Agent": " ".join(user_agent_parts),
            "key": self.config.api_key,
        }

        url = "/".join([self.config.api_server, endpoint])

        LOGGER.debug("Sending API request...URL: %s", url)
        LOGGER.debug("Sending API request...method: %s", method)
        # LOGGER.debug("Sending API request...headers: %s", headers)
        LOGGER.debug("Sending API request...params: %s", params)
        # LOGGER.debug("Sending API request...json: %s", json)
        LOGGER.debug("Sending API request...files: %s", files)
        LOGGER.debug("Sending API request...proxy: %s", proxy)

        # Build full URL with params for logging
        if params:
            full_url = f"{url}?{urlencode(params)}"
        else:
            full_url = url
        LOGGER.debug("Full request URL with parameters: %s", full_url)

        request_method = getattr(self.session, method)
        try:
            if proxy:
                proxies = {protocol: proxy for protocol in ("http", "https")}
                response = request_method(
                    url,
                    headers=headers,
                    timeout=self.config.timeout,
                    params=params,
                    json=json,
                    files=files,
                    proxies=proxies,
                )
            else:
                response = request_method(
                    url,
                    headers=headers,
                    timeout=self.config.timeout,
                    params=params,
                    json=json,
                    files=files,
                )

            content_type = response.headers.get("Content-Type", "")
            headers = response.headers

            if "application/json" in content_type:
                body = response.json()
            else:
                body = response.text

            # LOGGER.debug("API response received %s %s", response.status_code, body)

            if response.status_code == 429:
                raise RateLimitError()
            if response.status_code >= 400 and response.status_code != 404:
                raise RequestFailure(response.status_code, body)

            if include_headers:
                return body, headers
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
            future_to_chunk = {
                executor.submit(process_func, chunk): chunk for chunk in chunks
            }

            for future in as_completed(future_to_chunk):
                try:
                    chunk_results = future.result()
                    LOGGER.debug(f"Chunked Results: {chunk_results}")

                    if first_result_type is None:
                        first_result_type = type(chunk_results)
                        if first_result_type not in [list, dict]:
                            raise TypeError(
                                "Unsupported result type: must be list or dict"
                            )

                    if isinstance(chunk_results, list):
                        list_results.extend(chunk_results)
                    elif isinstance(chunk_results, dict):
                        for key, value in chunk_results.items():
                            if isinstance(value, list):
                                dict_results[key].extend(value)
                            else:
                                dict_results[key].append(value)
                        LOGGER.debug(f"dict results: {dict_results}")

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
    EP_GNQL_STATS = "v2/experimental/gnql/stats"
    EP_IP = "v3/ip/{ip_address}"
    EP_NOISE_MULTI = "v3/ip?quick=true"
    EP_NOISE_CONTEXT_MULTI = "v3/ip"
    EP_COMMUNITY_IP = "v3/community/{ip_address}"
    EP_SIMILARITY_IP = "v3/similarity/ips/{ip_address}"
    EP_TIMELINE_IP = "v3/noise/ips/{ip_address}/timeline"
    EP_TIMELINE_HOURLY_IP = "v3/noise/ips/{ip_address}/hourly-summary"
    EP_TIMELINE_DAILY_IP = "v3/noise/ips/{ip_address}/daily-summary"
    EP_META_METADATA = "v2/meta/metadata"
    EP_PING = "ping"
    EP_SENSOR_ACTIVITY = "v1/workspaces/{workspace_id}/sensors/activity"
    EP_SENSOR_LIST = "v1/workspaces/{workspace_id}/sensors"
    EP_PERSONA_DETAILS = "v1/personas/{persona_id}"
    EP_CVE_LOOKUP = "v1/cve/{cve_id}"
    EP_ANALYZE_UPLOAD = "v2/analyze/upload"
    EP_ANALYZE = "v2/analyze/{id}"
    EP_NOT_IMPLEMENTED = "v2/request/{subcommand}"
    UNKNOWN_CODE_MESSAGE = "Code message unknown: {}"

    IP_QUICK_CHECK_CHUNK_SIZE = 10000

    IPV4_REGEX = re.compile(
        r"(?:{octet}\.){{3}}{octet}".format(
            octet=r"(?:(?:25[0-5])|(?:2[0-4]\d)|(?:1?\d?\d))"
        )
    )

    def __init__(self, config: APIConfig):
        super().__init__(config)
        self.offering = config.offering

    def request(
        self,
        endpoint: str,
        method: str = "get",
        params: Optional[Dict[str, Any]] = None,
        json: Optional[Dict[str, Any]] = None,
        files: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, Any]] = None,
        proxy: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Make a request to the GreyNoise API.

        Args:
            endpoint: API endpoint to request
            method: HTTP method to use
            params: URL parameters to include
            json: JSON data to include
            files: Files to include
            headers: Headers to include
            proxy: Proxy URL to use for the request

        Returns:
            API response data
        """
        if headers is None:
            headers = {"key": self.config.api_key, "Accept": "application/json"}
        return self._request(
            endpoint,
            method=method,
            params=params,
            json=json,
            files=files,
            headers=headers,
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

            if "uuid" in upload:
                uuid = upload["uuid"]
                state = upload["state"]
                while state != "completed":
                    url = self.EP_ANALYZE.format(id=uuid)
                    response = self._request(url)
                    state = response["state"]
                    time.sleep(5)
                unique_ip_list = (
                    response["details"].get("noise_ips_found", [])
                    + response["details"].get("unknown_ips", [])
                    + response["details"].get("riot_ips_found", [])
                )

                text_stats["summary"] = {
                    "ip_count": response["details"].get("unique_ips", 0),
                    "noise_ip_count": response["details"].get("noise_ips", 0),
                    "not_noise_ip_count": response["details"].get("non_noise_ips", 0),
                    "riot_ip_count": response["details"].get("riot_ips", 0),
                    "noise_ip_ratio": response["details"].get(
                        "percentage_of_noise_ips", 0
                    ),
                    "riot_ip_ratio": response["details"].get(
                        "percentage_of_riot_ips", 0
                    ),
                }
                text_stats["stats"] = response.get("stats")
                text_stats["query"] = unique_ip_list
                text_stats["count"] = response["details"].get("unique_ips", 0)

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
        for filtered_chunk in gnfilter.filter(
            text, noise_only=noise_only, riot_only=riot_only
        ):
            yield filtered_chunk

    def ip(self, ip_address):  # pylint: disable=C0103
        """Get context associated with an IP address.

        :param ip_address: IP address to use in the look-up.
        :type ip_address: str
        :return: Context for the IP address.
        :rtype: dict

        """
        LOGGER.debug("Getting context for %s...", ip_address)
        validate_ip(ip_address)

        if self.offering.lower() == "community":
            endpoint = self.EP_COMMUNITY_IP.format(ip_address=ip_address)
        else:
            endpoint = self.EP_IP.format(ip_address=ip_address)
        if self.config.use_cache:
            cache = self.ip_context_cache
            response = (
                cache[ip_address]
                if ip_address in cache
                else cache.setdefault(ip_address, self._request(endpoint))
            )
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

    def query(self, query, size=None, scroll=None, exclude_raw=False, quick=False):
        """Run GNQL query."""
        if self.offering == "community":
            response = {"message": "GNQL not supported with Community offering"}
        else:
            LOGGER.debug(
                "Running GNQL query: %s %s %s %s...", query, size, scroll, quick
            )
            params = {"query": query, "quick": quick}
            if size is not None:
                params["size"] = size
            if scroll is not None:
                params["scroll"] = scroll
            response = self._request(self.EP_GNQL, params=params)

        if exclude_raw:
            if "data" in response:
                for ip_data in response["data"]:
                    ip_data["internet_scanner_intelligence"].pop("raw_data")

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
            ip_address
            for ip_address in ip_addresses
            if validate_ip(ip_address, strict=False, print_warning=False)
        ]

        def process_chunk(chunk: List[str]) -> List[Dict[str, Any]]:
            """Process a chunk of IP addresses."""
            api_result = self._request(
                self.EP_NOISE_MULTI, method="post", json={"ips": chunk}
            )
            return api_result

        # Process valid IPs in parallel batches
        if self.config.use_cache:
            # Keep the same ordering as in the input
            LOGGER.debug("Using cache for quick lookup")
            ordered_results = OrderedDict(
                (ip_address, self.ip_quick_check_cache.get(ip_address))
                for ip_address in valid_ip_addresses
            )
            api_ip_addresses = [
                ip_address
                for ip_address, result in ordered_results.items()
                if result is None
            ]

        else:
            LOGGER.debug("Not using cache for quick lookup")
            # Keep the same ordering as in the input
            ordered_results = OrderedDict(
                (ip_address, None) for ip_address in valid_ip_addresses
            )
            api_ip_addresses = [
                ip_address
                for ip_address, result in ordered_results.items()
                if result is None
            ]
        if api_ip_addresses:
            api_results = self._process_batch_parallel(
                api_ip_addresses,
                process_chunk,
                batch_size=self.IP_QUICK_CHECK_CHUNK_SIZE,
            )

            ip_results = []
            ips_not_found = []
            for key, values in api_results.items():
                if key == "data":
                    ip_results = values
                if key == "request_metadata":
                    for item in values:
                        ips_not_found.extend(item["ips_not_found"])

            for result in ip_results:
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

        def process_chunk(chunk: List[str]) -> List[Dict[str, Any]]:
            """Process a chunk of IP addresses."""
            api_result = self._request(
                self.EP_NOISE_CONTEXT_MULTI, method="post", json={"ips": chunk}
            )
            return api_result

        if self.offering == "community":  # pylint: disable=R1702
            results = [
                {"message": "IP Multi Lookup not supported with Community offering"}
            ]
        else:
            if isinstance(ip_addresses, str):
                ip_addresses = ip_addresses.split(",")

            LOGGER.debug("Getting noise context for %s IPs...", len(ip_addresses))

            valid_ip_addresses = [
                ip_address
                for ip_address in ip_addresses
                if validate_ip(ip_address, strict=False, print_warning=False)
            ]

            # Process valid IPs in parallel batches
            if self.config.use_cache:
                # Keep the same ordering as in the input
                LOGGER.debug("Using cache for quick lookup")
                ordered_results = OrderedDict(
                    (ip_address, self.ip_context_cache.get(ip_address))
                    for ip_address in valid_ip_addresses
                )
                api_ip_addresses = [
                    ip_address
                    for ip_address, result in ordered_results.items()
                    if result is None
                ]

            else:
                LOGGER.debug("Not using cache for quick lookup")
                # Keep the same ordering as in the input
                ordered_results = OrderedDict(
                    (ip_address, None) for ip_address in valid_ip_addresses
                )
                api_ip_addresses = [
                    ip_address
                    for ip_address, result in ordered_results.items()
                    if result is None
                ]
            if api_ip_addresses:
                api_results = self._process_batch_parallel(
                    api_ip_addresses,
                    process_chunk,
                    batch_size=self.IP_QUICK_CHECK_CHUNK_SIZE,
                )

                ip_results = []
                ips_not_found = []
                for key, values in api_results.items():
                    if key == "data":
                        ip_results = values
                    if key == "request_metadata":
                        for item in values:
                            ips_not_found.extend(item["ips_not_found"])

                for result in ip_results:
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

            results = [
                result for result in ordered_results.values() if result is not None
            ]

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

    def metadata(self):
        """Get metadata."""
        if self.offering == "community":
            response = {
                "message": "Metadata lookup not supported with Community offering"
            }
        else:
            LOGGER.debug("Getting metadata...")
            response = self._request(self.EP_META_METADATA)

        return response

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
            "The riot() function is deprecated and will be removed in"
            " a future version. Please use ip() instead."
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
        LOGGER.debug(
            "Running Sensor Activity: %s %s %s %s %s %s %s %s...",
            workspace_id,
            file_format,
            start_time,
            end_time,
            persona_id,
            source_ip,
            size,
            scroll,
        )
        if file_format is None or file_format == "json":
            params = {"format": "json"}
        elif file_format == "csv":
            params = {"format": file_format}
        else:
            LOGGER.error(
                f"Value for file_format is not valid (valid: json, csv): {file_format}"
            )
            sys.exit(1)

        if start_time is not None:
            params["start_time"] = start_time
        if end_time is not None:
            params["end_time"] = end_time
        if persona_id is not None:
            params["persona_id"] = persona_id
        if source_ip is not None:
            params["source_ip"] = source_ip
        if size is not None:
            params["size"] = size
        if scroll is not None:
            params["scroll"] = scroll
        endpoint = self.EP_SENSOR_ACTIVITY.format(workspace_id=workspace_id)
        response, headers = self._request(endpoint, params=params, include_headers=True)

        if include_headers:
            return response, headers
        else:
            return response

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
        """Get session data from sensors"""
        LOGGER.debug(
            "Running Sensor Activity: %s %s %s %s %s %s %s %s...",
            workspace_id,
            file_format,
            start_time,
            end_time,
            persona_id,
            source_ip,
            size,
            scroll,
        )
        if file_format is None or file_format == "json":
            params = {"format": "json"}
        elif file_format == "csv":
            params = {"format": file_format}
        else:
            LOGGER.error(
                f"Value for file_format is not valid (valid: json, csv): {file_format}"
            )
            sys.exit(1)

        if start_time is not None:
            params["start_time"] = start_time
        if end_time is not None:
            params["end_time"] = end_time
        if persona_id is not None:
            params["persona_id"] = persona_id
        if source_ip is not None:
            params["source_ip"] = source_ip
        if size is not None:
            params["size"] = size
        if scroll is not None:
            params["scroll"] = scroll
        endpoint = self.EP_SENSOR_ACTIVITY.format(workspace_id=workspace_id)
        response = self._request(endpoint, params=params)
        ip_list = []
        for item in response:
            ip_list.append(item.get("source_ip", ""))
        final_ip_list = list(set(ip_list))

        return final_ip_list

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
        if self.offering == "community":
            response = {
                "message": "Similarity lookup not supported with Community offering"
            }
        else:
            LOGGER.debug("Checking IP Sim results for %s...", ip_address)
            validate_ip(ip_address)

            if limit is None:
                limit = 50

            endpoint = self.EP_SIMILARITY_IP.format(ip_address=ip_address)
            endpoint = endpoint + f"?limit={limit}"

            if min_score:
                validate_similar_min_score(min_score)
                if min_score != 0:
                    min_score = min_score / 100
                endpoint = endpoint + f"&minimum_score={min_score}"

            response = self._request(endpoint)

            if "ip" not in response:
                response["ip"] = ip_address

        return response

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
            response = {
                "message": "Timeline lookup not supported with Community offering"
            }
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
        if self.offering == "community":
            response = {
                "message": "Timeline lookup not supported with Community offering"
            }
        else:
            LOGGER.debug("Checking IP Timeline results for %s...", ip_address)
            validate_ip(ip_address)
            if days:
                validate_timeline_days(days)

            endpoint = self.EP_TIMELINE_HOURLY_IP.format(ip_address=ip_address)
            endpoint = endpoint + f"?limit={limit}"
            if days:
                endpoint = endpoint + f"&days={days}"
            if cursor:
                endpoint = endpoint + f"&cursor={cursor}"
            response = self._request(endpoint)

            if "ip" not in response:
                response["ip"] = ip_address

        return response

    def timelinedaily(self, ip_address, days=None, cursor=None, limit=50):
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
            response = {
                "message": "Timeline lookup not supported with Community offering"
            }
        else:
            LOGGER.debug("Checking IP Timeline results for %s...", ip_address)
            validate_ip(ip_address)
            if days:
                validate_timeline_days(days)

            endpoint = self.EP_TIMELINE_DAILY_IP.format(ip_address=ip_address)
            endpoint = endpoint + f"?limit={limit}"
            if days:
                endpoint = endpoint + f"&days={days}"
            if cursor:
                endpoint = endpoint + f"&cursor={cursor}"
            response = self._request(endpoint)

            if "ip" not in response:
                response["ip"] = ip_address

        return response

    def sensor_list(self, workspace_id=None):
        """Get list of current sensors for Workspace

        :param workspace_id: ID of Workspace
        :type workspace_id: str


        """
        if self.offering == "community":
            response = {
                "message": "Sensors List is not supported with Community offering"
            }
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
            response = {
                "message": "Persona Details is not supported with Community offering"
            }
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
            response = {
                "message": "CVE lookup is not supported with Community offering"
            }
        else:
            LOGGER.debug("Getting Details for CVE ID: %s...", cve_id)

            # check if CVE submitted is in correct format
            validate_cve_id(cve_id)

            endpoint = self.EP_CVE_LOOKUP.format(cve_id=cve_id)
            response = self._request(endpoint)

        return response
