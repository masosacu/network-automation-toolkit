#!/usr/bin/env python3

"""
Cisco Inventory Collection Script

Reads Cisco device IP addresses from management_ips.txt,
connects via SSH using Netmiko,
retrieves:

    - Hostname
    - Product ID (PID)
    - Serial Number

Outputs:

    cisco_inventory.csv
    failed_devices.log
    automation.log

Author: Your Name
"""

import csv
import getpass
import ipaddress,getpass,csv,logging,re
import logging
import re
from pathlib import Path

from netmiko import ConnectHandler
from netmiko.exceptions import (
    NetmikoAuthenticationException,
    NetmikoTimeoutException,
)

###########################################################################
# Configuration
###########################################################################

BASE_DIR=Path(__file__).resolve().parent
INPUT_FILE=BASE_DIR/"management_ips.txt"
OUTPUT_CSV=BASE_DIR/"cisco_inventory.csv"
FAILED_LOG=BASE_DIR/"failed_devices.log"
LOG_FILE=BASE_DIR/"automation.log"


# Placeholder for future Cisco API Integration
CLIENT_ID = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"

###########################################################################
# Logging
###########################################################################

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)

###########################################################################
# Functions
###########################################################################


def load_management_ips(filename):
    """
    Reads IP addresses from file.
    Validates each address.
    Ignores blank lines and comments.
    """

    valid_ips = []

    with open(filename) as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            try:
                ipaddress.ip_address(line)
                valid_ips.append(line)

            except ValueError:
                logging.warning(f"Invalid IP skipped: {line}")

    return valid_ips


###########################################################################


def parse_inventory(show_inventory):
    """
    Parse PID and Serial from 'show inventory'
    """

    pid = "Unknown"
    serial = "Unknown"

    pid_match = re.search(r"PID:\s*([^,\s]+)", show_inventory)

    serial_match = re.search(r"SN:\s*([^\s,]+)", show_inventory)

    if pid_match:
        pid = pid_match.group(1)

    if serial_match:
        serial = serial_match.group(1)

    return pid, serial


###########################################################################


def get_hostname(show_version):
    """
    Parse hostname from show version.
    """

    for line in show_version.splitlines():

        if " uptime is " in line:
            return line.split(" uptime")[0].strip()

    return "Unknown"


###########################################################################


def connect_device(ip, username, password):
    """
    Connects to Cisco device
    Collects inventory information
    """

    device = {
        "device_type": "cisco_ios",
        "host": ip,
        "username": username,
        "password": password,
        "fast_cli": False,
    }

    try:

        connection = ConnectHandler(**device)

        show_version = connection.send_command(
            "show version",
            read_timeout=60,
        )

        show_inventory = connection.send_command(
            "show inventory",
            read_timeout=60,
        )

        hostname = get_hostname(show_version)

        pid, serial = parse_inventory(show_inventory)

        connection.disconnect()

        logging.info(f"SUCCESS {ip}")

        return {
            "Hostname": hostname,
            "Management IP": ip,
            "PID": pid,
            "Serial": serial,
        }

    except NetmikoAuthenticationException:

        logging.error(f"Authentication Failed: {ip}")

        with open(FAILED_LOG, "a") as f:
            f.write(f"{ip},Authentication Failed\n")

    except NetmikoTimeoutException:

        logging.error(f"Timeout: {ip}")

        with open(FAILED_LOG, "a") as f:
            f.write(f"{ip},Timeout\n")

    except Exception as e:

        logging.exception(f"{ip}")

        with open(FAILED_LOG, "a") as f:
            f.write(f"{ip},{str(e)}\n")

    return None


###########################################################################


def save_csv(results):
    """
    Save results to CSV
    """

    with open(OUTPUT_CSV, "w", newline="") as csvfile:

        writer = csv.DictWriter(
            csvfile,
            fieldnames=[
                "Hostname",
                "Management IP",
                "PID",
                "Serial",
            ],
        )

        writer.writeheader()

        writer.writerows(results)


###########################################################################
# Main
###########################################################################

def main():

    print("\nCisco Inventory Collection\n")

    username = input("SSH Username: ")

    password = getpass.getpass("SSH Password: ")

    ips = load_management_ips(INPUT_FILE)

    print(f"\nFound {len(ips)} valid IP addresses.\n")

    results = []

    for ip in ips:

        print(f"Connecting to {ip}...")

        info = connect_device(ip, username, password)

        if info:
            results.append(info)

    save_csv(results)

    print("\nCompleted.")

    print(f"Successful devices : {len(results)}")

    print(f"CSV Output         : {OUTPUT_CSV}")

    print(f"Failed Log         : {FAILED_LOG}")

    print(f"Automation Log     : {LOG_FILE}")


###########################################################################

if __name__ == "__main__":
    main()