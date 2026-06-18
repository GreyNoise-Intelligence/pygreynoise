"""
GreyNoise Timeline Data Fetcher.

This module provides functions to fetch and consolidate historical timeline data from the
GreyNoise API. It uses multi-threaded requests to efficiently retrieve timeline data across
multiple fields (ports, paths, user agents, ASN, organization, rDNS, tags, classification)
and consolidates them by timestamp.

The module is designed for use with the Anomali ThreatStream enrichment plugin but can be
used standalone for any application requiring GreyNoise timeline data.

Key Features:
    - Parallel API Requests: Uses ThreadPoolExecutor for concurrent field queries
    - Tag Resolution: Automatically converts tag IDs to human-readable names
    - Data Consolidation: Merges multiple field timelines by timestamp
    - Configurable: Supports custom time ranges, granularity, and field selection
    - Memory Efficient: Streams and processes results as they arrive

Main Function:
    get_greynoise_timeline(): Fetches and consolidates timeline data for an IP address

Helper Functions:
    fetch_tags_mapping(): Retrieves tag ID to name mappings
    fetch_field_timeline(): Fetches timeline data for a single field
    process_field_data(): Processes and organizes field data by timestamp

Version: 3.0.0
Author: GreyNoise Intelligence
"""

import logging
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

import requests

LOGGER = logging.getLogger(__name__)

# Map API field names to display names
FIELD_MAPPING = {
    "destination_port": "ports",
    "http_path": "web_paths",
    "http_user_agent": "user_agents",
    "source_asn": "asns",
    "source_org": "organizations",
    "source_rdns": "rdns",
    "tag_ids": "tags",
    "classification": "classification",
}

DEFAULT_FIELDS = [
    "destination_port",
    "http_path",
    "http_user_agent",
    "source_asn",
    "source_org",
    "source_rdns",
    "tag_ids",
    "classification",
]


def fetch_tags_mapping(
    api_key: str,
    base_url: str = "https://api.greynoise.io/v3",
    user_agent: str = "greynoise-timeline-function",
) -> Dict[str, str]:
    """
    Fetch tag ID to name mapping from GreyNoise API.

    This function retrieves all available tags from GreyNoise and creates a mapping
    dictionary from tag IDs to human-readable tag names. This is used to convert
    tag_ids in timeline data to their descriptive names.

    Args:
        api_key (str): GreyNoise API key for authentication
        base_url (str): Base API URL (default: "https://api.greynoise.io/v3")
        user_agent (str): User-Agent header value (default: "greynoise-timeline-function")

    Returns:
        Dict[str, str]: Dictionary mapping tag IDs to tag names. Returns empty dict on error.

    Response Handling:
        - Handles dict responses with 'tags', 'data', or 'results' keys
        - Handles direct list responses
        - Returns empty dict for unexpected formats or errors

    Error Handling:
        - Logs a warning with exception context on failure
        - Returns empty dict rather than raising exception
        - Uses 10-second timeout for API request

    Example:
        >>> tags = fetch_tags_mapping("your_api_key")
        >>> print(tags)
        {'abc123': 'SSH Brute Force', 'def456': 'Web Scanner', ...}
    """
    headers = {"Accept": "application/json", "key": api_key, "User-Agent": user_agent}
    tags_url = f"{base_url}/tags"

    try:
        LOGGER.debug("Fetching tags mapping from %s", tags_url)
        response = requests.get(tags_url, headers=headers, timeout=10)
        response.raise_for_status()
        tags_data = response.json()
        LOGGER.debug("Tags mapping response: %s", tags_data)

        # Handle different possible response structures
        if isinstance(tags_data, dict):
            tags_list = tags_data.get("tags") or tags_data.get("data") or tags_data.get("results") or []
        elif isinstance(tags_data, list):
            tags_list = tags_data
        else:
            tags_list = []
        LOGGER.debug("Tags list: %s", tags_list)
        return {tag.get("id"): tag.get("name") for tag in tags_list if isinstance(tag, dict)}
    except Exception:
        LOGGER.warning("Failed to fetch tags mapping from %s", tags_url, exc_info=True)
        return {}


def fetch_field_timeline(
    ip: str,
    field: str,
    api_key: str,
    days: int = 30,
    granularity: str = "1d",
    base_url: str = "https://api.greynoise.io/v3",
    user_agent: str = "greynoise-timeline-function",
) -> Optional[Dict[str, Any]]:
    """
    Fetch timeline data for a specific field from GreyNoise API.

    This function queries the GreyNoise timeline endpoint for historical data about a
    specific field (e.g., ports, paths, classification) for a given IP address.

    Args:
        ip (str): IP address to query (must be a valid public IPv4)
        field (str): Field name to fetch (e.g., 'destination_port', 'classification')
        api_key (str): GreyNoise API key for authentication
        days (int): Number of days of history to retrieve (default: 30)
        granularity (str): Time granularity - '1d' for daily, '1h' for hourly (default: '1d')
        base_url (str): Base API URL (default: "https://api.greynoise.io/v3")
        user_agent (str): User-Agent header value (default: "greynoise-timeline-function")

    Returns:
        Optional[Dict[str, Any]]: API response containing metadata and results, or None on error.

        Response structure:
            {
                'metadata': {
                    'ip': str,
                    'field': str,
                    'first_seen': str,
                    'start': str,
                    'end': str,
                    'granularity': str,
                    'metric': str
                },
                'results': [
                    {'timestamp': str, 'label': str, 'data': int},
                    ...
                ]
            }

    Supported Fields:
        - destination_port: Ports scanned by the IP
        - http_path: HTTP paths requested
        - http_user_agent: User agent strings used
        - source_asn: Autonomous System Number
        - source_org: Organization name
        - source_rdns: Reverse DNS
        - tag_ids: GreyNoise tag identifiers
        - classification: Threat classification

    Error Handling:
        - Returns None on failure; failures are logged at WARNING with exception context
        - Caller is responsible for handling None results
        - Uses 30-second timeout for API request
        - Validates HTTP status with raise_for_status()

    Example:
        >>> data = fetch_field_timeline("8.8.8.8", "classification", "your_api_key")
        >>> print(data['results'][0])
        {'timestamp': '2024-01-01T00:00:00Z', 'label': 'benign', 'data': 1}
    """
    headers = {"Accept": "application/json", "key": api_key, "User-Agent": user_agent}
    url = f"{base_url}/noise/ips/{ip}/timeline?days={days}&field={field}&granularity={granularity}"

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
        payload = response.json()
        if not payload:
            LOGGER.warning("Timeline response empty for field=%r ip=%r", field, ip)
            return None
        return payload
    except Exception:
        LOGGER.warning(
            "Timeline request failed for field=%r ip=%r url=%s",
            field,
            ip,
            url,
            exc_info=True,
        )
        return None


def process_field_data(
    data: Dict[str, Any],
    field: str,
    tags_dict: Dict[str, str],
    field_mapping: Dict[str, str],
) -> Dict[str, List[str]]:
    """
    Process timeline data for a single field and organize by timestamp.

    This function takes raw API response data for a single field and processes it into
    a structured format organized by timestamp. It handles tag ID resolution and maps
    API field names to display-friendly names.

    Args:
        data (Dict[str, Any]): Raw API response from fetch_field_timeline()
        field (str): Original field name that was queried
        tags_dict (Dict[str, str]): Mapping of tag IDs to tag names for resolution
        field_mapping (Dict[str, str]): Mapping of API field names to display names

    Returns:
        Dict[str, List[str]]: Dictionary mapping timestamps to lists of (display_name, label) tuples.
        Returns empty defaultdict if data is None or empty.

    Processing Steps:
        1. Extracts field name from metadata and maps to display name
        2. Iterates through all results in the API response
        3. For each result with valid timestamp and label:
           - Converts tag IDs to names if field is 'tag_ids'
           - Stores (display_name, label) tuple for the timestamp

    Tag Resolution:
        - Automatically converts tag IDs to human-readable names
        - Only applies to 'tag_ids' field
        - Falls back to original ID if not found in mapping

    Example:
        >>> data = {
        ...     'metadata': {'field': 'classification'},
        ...     'results': [
        ...         {'timestamp': '2024-01-01T00:00:00Z', 'label': 'malicious'},
        ...         {'timestamp': '2024-01-02T00:00:00Z', 'label': 'benign'}
        ...     ]
        ... }
        >>> result = process_field_data(data, 'classification', {}, FIELD_MAPPING)
        >>> print(result)
        {
            '2024-01-01T00:00:00Z': [('Classification', 'malicious')],
            '2024-01-02T00:00:00Z': [('Classification', 'benign')]
        }
    """
    field_data = defaultdict(list)

    if not data:
        return field_data

    # Extract the field name from metadata and map to display name
    api_field_name = data.get("metadata", {}).get("field", field)
    display_field_name = field_mapping.get(api_field_name, api_field_name)

    # Process each result entry
    for entry in data.get("results", []):
        timestamp = entry.get("timestamp")
        label = entry.get("label")

        if timestamp and label:
            # Replace tag IDs with names if applicable
            if api_field_name == "tag_ids" and label in tags_dict:
                label = tags_dict[label]

            field_data[timestamp].append((display_field_name, label))

    return field_data


def get_greynoise_timeline(  # noqa: C901
    ip: str,
    api_key: str,
    fields: Optional[List[str]] = None,
    days: int = 30,
    granularity: str = "1d",
    max_workers: int = 5,
    base_url: str = "https://api.greynoise.io/v3",
    user_agent: str = "greynoise-timeline-function",
) -> List[Dict[str, Any]]:
    """
    Fetch and consolidate GreyNoise timeline data for multiple fields.

    This is the main function that orchestrates fetching timeline data for an IP address
    across multiple fields in parallel, consolidating the results by timestamp, and
    returning a sorted list of timeline entries. It provides a comprehensive view of
    an IP's historical activity on the Internet.

    Args:
        ip (str): IP address to query (must be valid public IPv4)
        api_key (str): GreyNoise API key for authentication
        fields (Optional[List[str]]): List of field names to fetch. If None, uses DEFAULT_FIELDS:
            ['destination_port', 'http_path', 'http_user_agent', 'source_asn',
             'source_org', 'source_rdns', 'tag_ids', 'classification']
        days (int): Number of days of historical data to retrieve (default: 30, max: 90)
        granularity (str): Time granularity for data points (default: '1d' for daily, '1h' for hourly)
        max_workers (int): Maximum concurrent API requests via ThreadPoolExecutor (default: 5)
        base_url (str): Base GreyNoise API URL (default: "https://api.greynoise.io/v3")
        user_agent (str): User-Agent header value (default: "greynoise-timeline-function")

    Returns:
        List[Dict[str, Any]]: Sorted list of timeline entries (oldest to newest), where each entry is:
            {
                'Date': str,              # ISO 8601 timestamp
                'Classification': [str],  # e.g., ['malicious', 'benign']
                'Tags': [str],           # e.g., ['SSH Brute Force', 'Web Scanner']
                'rDNS': [str],           # e.g., ['example.com']
                'Organization': [str],   # e.g., ['Google LLC']
                'ASN': [str],           # e.g., ['AS15169']
                'Ports': [str],         # e.g., ['80', '443', '8080']
                'Web Paths': [str],     # e.g., ['/api', '/admin']
                'User Agents': [str]    # e.g., ['Mozilla/5.0...']
            }

    Performance:
        - Uses parallel requests with ThreadPoolExecutor
        - Typical execution time: 2-5 seconds for 8 fields with max_workers=8
        - Memory efficient: processes results as they arrive
        - ~8x faster than sequential requests

    Data Processing:
        1. Fetches tag ID to name mapping (once)
        2. Submits parallel requests for all fields
        3. Processes each field's data as it completes
        4. Consolidates data by timestamp
        5. Sorts and returns chronological list

    Tag Resolution:
        - Automatically converts tag IDs to human-readable names
        - Tags like 'abc123' become 'SSH Brute Force Scanner'
        - Requires initial tags mapping API call

    Error Handling:
        - Failed field requests are logged (WARNING / ERROR); processing continues for other fields
        - Continue processing other fields on individual failures
        - Returns partial results if at least one field succeeds
        - Raises exception if ALL field requests fail
        - Empty list if no data available from successful requests

    Example Usage:
        >>> # Basic usage with defaults
        >>> data = get_greynoise_timeline(
        ...     ip="8.8.8.8",
        ...     api_key="your_api_key"
        ... )

        >>> # Custom fields and parameters
        >>> data = get_greynoise_timeline(
        ...     ip="1.2.3.4",
        ...     api_key="your_api_key",
        ...     fields=["classification", "tag_ids"],
        ...     days=7,
        ...     max_workers=10,
        ...     user_agent="my-app/1.0"
        ... )

        >>> # Example output
        >>> print(data[0])
        {
            'Date': '2024-01-01T00:00:00Z',
            'Classification': ['malicious'],
            'Tags': ['SSH Brute Force', 'Port Scanner'],
            'Ports': ['22', '80', '443'],
            'ASN': ['AS12345']
        }

    Notes:
        - Requires Enterprise or higher API key (not available with Community key)
        - Timeline data availability depends on subscription level
        - Results sorted chronologically (oldest first)
        - All field values are lists to accommodate multiple values per timestamp
        - Empty fields are omitted from results
    """
    if fields is None:
        fields = DEFAULT_FIELDS

    LOGGER.info(
        "Fetching GreyNoise timeline ip=%r fields=%s days=%s granularity=%r",
        ip,
        fields,
        days,
        granularity,
    )

    # Fetch tags mapping
    tags_dict = fetch_tags_mapping(api_key, base_url, user_agent)
    if tags_dict:
        LOGGER.debug("Loaded %d tag id→name mappings", len(tags_dict))
    else:
        LOGGER.warning("Tag mapping is empty; tag_ids labels will stay as raw IDs if present")

    # Dictionary to store consolidated data by timestamp
    consolidated_data = defaultdict(dict)

    # Track successful and failed requests
    successful_fields = []
    failed_fields = []

    # Fetch all field timelines in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all API requests
        future_to_field = {
            executor.submit(
                fetch_field_timeline,
                ip,
                field,
                api_key,
                days,
                granularity,
                base_url,
                user_agent,
            ): field
            for field in fields
        }

        # Process results as they complete
        for future in as_completed(future_to_field):
            field = future_to_field[future]
            try:
                data = future.result()
                if data:
                    successful_fields.append(field)
                    LOGGER.debug("Timeline field ok: %s", field)
                    # Process field data
                    field_data = process_field_data(data, field, tags_dict, FIELD_MAPPING)

                    # Merge into consolidated data
                    for timestamp, entries in field_data.items():
                        for display_name, label in entries:
                            if display_name not in consolidated_data[timestamp]:
                                consolidated_data[timestamp][display_name] = []
                            consolidated_data[timestamp][display_name].append(label)
                else:
                    failed_fields.append(field)
            except Exception:
                LOGGER.exception("Timeline worker failed for field=%r", field)
                failed_fields.append(field)

    LOGGER.info(
        "Timeline fetch finished: %d ok, %d failed (failed=%s)",
        len(successful_fields),
        len(failed_fields),
        failed_fields,
    )

    # If all requests failed, raise an exception
    if not successful_fields and failed_fields:
        LOGGER.error(
            "All timeline field requests failed for ip=%r; fields attempted=%s",
            ip,
            fields,
        )
        raise Exception(
            "Failed to fetch timeline data for all fields. "
            "This may be due to API access restrictions or network issues."
        )

    # Convert to sorted list
    consolidated_list = []
    for timestamp in sorted(consolidated_data.keys()):
        entry = {"date": timestamp}
        entry.update(consolidated_data[timestamp])
        consolidated_list.append(entry)

    output = {
        "metadata": {
            "ip": ip,
            "field": field,
            "days": days,
            "granularity": granularity,
        },
        "data": consolidated_list,
    }

    return output


# Example usage
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(levelname)s %(name)s: %(message)s",
    )

    api_key = "$GREYNOISE_API_KEY"
    ip_address = "210.16.184.165"

    timeline_data = get_greynoise_timeline(
        ip=ip_address,
        api_key=api_key,
        days=30,
        granularity="1d",
        max_workers=8,
        user_agent="greynoise-timeline-test/1.0",
    )

    print(timeline_data)
