#!/usr/bin/env python3
"""
Example script demonstrating IP lookup functionality with GreyNoise API.
"""

import logging

from greynoise.api import APIConfig, GreyNoise

# Set up logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def main():
    # Create configuration
    config = APIConfig(
        api_key="your-api-key-here",  # Replace with your actual API key
        api_server="https://api.greynoise.io",
        timeout=30,
        proxy=None,
        offering="enterprise",  # or "community" depending on your subscription
    )

    # Initialize client
    client = GreyNoise(config)

    # Example 1: Single IP lookup
    try:
        ip_address = "8.8.8.8"  # Google's DNS server
        logger.info(f"Looking up information for IP: {ip_address}")
        result = client.ip(ip_address)

        # Print the results in a readable format
        logger.info("\nSingle IP Lookup Results:")
        logger.info(f"IP: {result.get('ip')}")
        logger.info(f"Classification: {result.get('classification')}")
        logger.info(f"Last Seen: {result.get('last_seen')}")
        logger.info(f"Name: {result.get('name')}")
        logger.info(f"Link: {result.get('link')}")

        # Print raw data for reference
        logger.info("\nRaw Response:")
        logger.info(result)
    except Exception as e:
        logger.error(f"Error during single IP lookup: {e}")

    # Example 2: Multiple IP lookup
    try:
        ip_addresses = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]  # Common DNS servers
        logger.info(f"\nLooking up information for multiple IPs: {ip_addresses}")
        results = client.quick(ip_addresses)

        # Print the results in a readable format
        logger.info("\nMultiple IP Lookup Results:")
        for result in results:
            logger.info(f"\nIP: {result.get('ip')}")
            logger.info(f"Classification: {result.get('classification')}")
            logger.info(f"Last Seen: {result.get('last_seen')}")
            logger.info(f"Name: {result.get('name')}")
    except Exception as e:
        logger.error(f"Error during multiple IP lookup: {e}")

    # Example 3: Detailed IP context lookup
    try:
        ip_address = "8.8.8.8"
        logger.info(f"\nGetting detailed context for IP: {ip_address}")
        result = client.ip_multi([ip_address])

        # Print the results in a readable format
        logger.info("\nDetailed IP Context Results:")
        for item in result:
            logger.info(f"\nIP: {item.get('ip')}")
            logger.info("Metadata:")
            for key, value in item.get("metadata", {}).items():
                logger.info(f"  {key}: {value}")
            logger.info("Tags:")
            for tag in item.get("tags", []):
                logger.info(f"  - {tag}")
    except Exception as e:
        logger.error(f"Error during detailed IP context lookup: {e}")


if __name__ == "__main__":
    main()
