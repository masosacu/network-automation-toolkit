#!/usr/bin/env python3
"""
MAC Address Format Converter

Reads MAC addresses in the format:
    xx.xx.xx.xx.xx.xx

Converts them to:
    yyyy.yyyy.yyyy

Example:
    Input : aa.bb.cc.dd.ee.ff
    Output: aabb.ccdd.eeff

Author: Manuel Sosa | Senior Network Engineer
"""

import re
import sys
from pathlib import Path

# Get the directory where this script resides
SCRIPT_DIR = Path(__file__).resolve().parent

# Input and output files located in the same directory as the script
INPUT_FILE = SCRIPT_DIR / "mac_addresses.txt"
OUTPUT_FILE = SCRIPT_DIR / "converted_mac_addresses.txt"

# Pattern for xx.xx.xx.xx.xx.xx
MAC_PATTERN = re.compile(
    r'^([0-9A-Fa-f]{2}\.){5}[0-9A-Fa-f]{2}$'
)


def convert_mac(mac):
    """
    Convert xx.xx.xx.xx.xx.xx
    to yyyy.yyyy.yyyy
    """
    mac = mac.lower().replace(".", "")
    return ".".join([
        mac[0:4],
        mac[4:8],
        mac[8:12]
    ])


def main():

    print(f"Script directory : {SCRIPT_DIR}")
    print(f"Looking for      : {INPUT_FILE}")

    # Verify the input file exists
    if not INPUT_FILE.is_file():
        print("\nERROR: Input file not found.")
        print(f"Expected location:\n{INPUT_FILE}")
        print("\nPlease place 'mac_addresses.txt' in the same directory as this script.")
        sys.exit(1)

    converted = []
    invalid = []

    with INPUT_FILE.open("r", encoding="utf-8") as infile:
        for line_number, line in enumerate(infile, start=1):
            mac = line.strip()

            if not mac:
                continue

            if MAC_PATTERN.fullmatch(mac):
                converted.append(convert_mac(mac))
            else:
                invalid.append((line_number, mac))

    with OUTPUT_FILE.open("w", encoding="utf-8") as outfile:
        for mac in converted:
            outfile.write(mac + "\n")

    print("=" * 50)
    print("Conversion Complete")
    print("=" * 50)
    print(f"Valid MAC addresses   : {len(converted)}")
    print(f"Invalid MAC addresses : {len(invalid)}")
    print(f"Output file           : {OUTPUT_FILE}")

    if invalid:
        print("\nInvalid entries:")
        for line_num, mac in invalid:
            print(f" Line {line_num}: {mac}")


if __name__ == "__main__":
    main()