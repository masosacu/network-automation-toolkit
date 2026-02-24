#!/usr/bin/env python3
"""
Peer-to-Peer Connectivity Traffic Generator

This script tests connectivity to predefined Peer-to-Peer (P2P) related URLs
by sending HTTP HEAD requests in sets. It requires three successful sets
to complete execution. A set is considered successful only if all requests
within that set succeed.

Features:
- Retries failed sets
- Configurable wait intervals between successful sets
- Dynamic console progress bar
- Robust error handling
- Logging to file and console
- Production-quality modular structure

Python Version: 3.8+
"""

import logging
import sys
import time
from typing import List

import requests
import urllib3
from requests.exceptions import (
    ConnectionError,
    Timeout,
    RequestException,
)

# Disable SSL warnings (equivalent to curl -k)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# -----------------------------
# Configuration
# -----------------------------

URLS: List[str] = [
    "https://www.bittorrent.com/",
    "https://www.utorrent.com/",
    "https://www.transmissionbt.com/",
    "https://www.qbittorrent.org/",
]

SUCCESSFUL_SETS_REQUIRED: int = 3
REQUEST_TIMEOUT: int = 10
LOG_FILE: str = "traffic_generation.log"


# -----------------------------
# Logging Configuration
# -----------------------------

def configure_logging() -> None:
    """
    Configure logging to file and console with appropriate formatting.
    """
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(message)s"
    )

    # File handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


# -----------------------------
# Utility Functions
# -----------------------------

def show_loading_bar(completed: int, total: int) -> None:
    """
    Display a dynamic loading bar in the console.

    :param completed: Number of completed successful sets.
    :param total: Total required successful sets.
    """
    percentage = int((completed / total) * 100)
    bar_length = 50
    filled_length = int(bar_length * completed // total)
    bar = "#" * filled_length + "-" * (bar_length - filled_length)

    sys.stdout.write(f"\rProgress: |{bar}| {percentage}% Complete")
    sys.stdout.flush()

    if completed == total:
        print()  # Move to next line when complete


def send_head_request(url: str) -> bool:
    """
    Send an HTTP HEAD request to a URL.

    :param url: Target URL.
    :return: True if request succeeds, False otherwise.
    """
    try:
        response = requests.head(
            url,
            timeout=REQUEST_TIMEOUT,
            verify=False,
            allow_redirects=True,
        )

        if 200 <= response.status_code < 400:
            logging.info(f"Request succeeded: {url} (Status: {response.status_code})")
            print(f"✔ SUCCESS: {url}")
            return True
        else:
            logging.warning(
                f"Unexpected status code for {url}: {response.status_code}"
            )
            print(f"✖ FAILED: {url} (Status: {response.status_code})")
            return False

    except Timeout:
        logging.error(f"Timeout occurred while connecting to {url}")
        print(f"✖ TIMEOUT: {url}")
    except ConnectionError:
        logging.error(f"Connection error occurred while connecting to {url}")
        print(f"✖ CONNECTION ERROR: {url}")
    except RequestException as exc:
        logging.error(f"Request exception for {url}: {exc}")
        print(f"✖ REQUEST ERROR: {url}")
    except Exception as exc:
        logging.exception(f"Unexpected error for {url}: {exc}")
        print(f"✖ UNEXPECTED ERROR: {url}")

    return False


def run_request_set(urls: List[str], set_number: int) -> bool:
    """
    Run a single request set (one HEAD request per URL).

    A set is successful only if all URL requests succeed.

    :param urls: List of URLs.
    :param set_number: Current set attempt number.
    :return: True if set successful, False otherwise.
    """
    print(f"\nStarting request set #{set_number}")
    logging.info(f"Starting request set #{set_number}")

    all_success = True

    for url in urls:
        success = send_head_request(url)
        if not success:
            all_success = False

    if all_success:
        logging.info(f"Set #{set_number} completed successfully.")
        print(f"Set #{set_number} SUCCESSFUL.")
    else:
        logging.warning(f"Set #{set_number} failed. Retrying...")
        print(f"Set #{set_number} FAILED. Retrying...")

    return all_success


def wait_between_sets(successful_sets: int) -> None:
    """
    Wait between successful sets based on the required logic.

    :param successful_sets: Number of successful sets completed.
    """
    if successful_sets == 1:
        wait_time = 30
    elif successful_sets == 2:
        wait_time = 5
    else:
        return

    logging.info(f"Waiting {wait_time} seconds before next set.")
    print(f"Waiting {wait_time} seconds before next set...")

    for remaining in range(wait_time, 0, -1):
        sys.stdout.write(f"\rResuming in {remaining} seconds...")
        sys.stdout.flush()
        time.sleep(1)

    print("\nResuming execution...")


# -----------------------------
# Main Execution
# -----------------------------

def main() -> None:
    """
    Main execution logic.
    """
    configure_logging()

    print("Peer-to-Peer Connectivity Traffic Generator Starting...")
    logging.info("Process started.")

    successful_sets = 0
    attempt_counter = 1

    try:
        while successful_sets < SUCCESSFUL_SETS_REQUIRED:
            success = run_request_set(URLS, attempt_counter)

            if success:
                successful_sets += 1
                show_loading_bar(successful_sets, SUCCESSFUL_SETS_REQUIRED)
                wait_between_sets(successful_sets)

            attempt_counter += 1

        print("\nAll required successful sets completed.")
        logging.info("Process completed successfully.")

    except KeyboardInterrupt:
        logging.warning("Process interrupted by user.")
        print("\nProcess interrupted by user. Exiting gracefully.")
    except Exception as exc:
        logging.exception(f"Fatal unexpected error: {exc}")
        print("\nA fatal unexpected error occurred. Check logs for details.")


if __name__ == "__main__":
    main()