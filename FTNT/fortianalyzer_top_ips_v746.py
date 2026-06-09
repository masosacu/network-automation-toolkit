#!/usr/bin/env python3

import requests
import getpass
import logging
import ipaddress
import re
import os

from netmiko import ConnectHandler
from requests.exceptions import RequestException

requests.packages.urllib3.disable_warnings()

# ------------------------------------------------
# Logging
# ------------------------------------------------

logging.basicConfig(
    filename="netmiko_debug.log",
    level=logging.DEBUG
)

FAILED_LOG = "failed_devices.log"

# ------------------------------------------------
# Validate hostname
# ------------------------------------------------

def valid_hostname(host):

    regex = r"^(?=.{1,253}$)([a-zA-Z0-9][-a-zA-Z0-9]{0,62})(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})*$"

    return re.match(regex, host) is not None


# ------------------------------------------------
# Read devices file (improved)
# ------------------------------------------------

def read_devices(file_name="FTAZ_hosts.txt"):

    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(script_dir, file_name)

    devices = []
    seen = set()

    print(f"[INFO] Reading device list from {file_path}")

    try:

        with open(file_path, "r", encoding="utf-8") as f:

            for line_number, line in enumerate(f, 1):

                device = line.strip()

                # Ignore blank lines
                if not device:
                    continue

                # Ignore comments
                if device.startswith("#"):
                    continue

                # Validate IP
                valid = False

                try:
                    ipaddress.ip_address(device)
                    valid = True
                except ValueError:
                    if valid_hostname(device):
                        valid = True

                if not valid:
                    print(f"[WARNING] Invalid host at line {line_number}: {device}")
                    continue

                if device in seen:
                    print(f"[WARNING] Duplicate entry at line {line_number}: {device}")
                    continue

                seen.add(device)
                devices.append(device)

        print(f"[INFO] Loaded {len(devices)} valid device(s)")

        return devices

    except FileNotFoundError:

        print(f"[ERROR] File not found: {file_path}")
        return []

    except Exception as e:

        print(f"[ERROR] Failed reading device file: {e}")
        return []


# ------------------------------------------------
# Log failed device
# ------------------------------------------------

def log_failed_device(host, reason):

    with open(FAILED_LOG, "a") as f:
        f.write(f"{host} : {reason}\n")


# ------------------------------------------------
# API Login
# ------------------------------------------------

def api_login(host, username, password):

    url = f"https://{host}/jsonrpc"

    payload = {
        "method": "exec",
        "params": [{
            "url": "/sys/login/user",
            "data": {
                "user": username,
                "passwd": password
            }
        }],
        "id": 1
    }

    try:

        r = requests.post(url, json=payload, verify=False, timeout=10)

        if r.status_code == 200:

            data = r.json()

            return data.get("session")

    except RequestException:

        pass

    return None


# ------------------------------------------------
# API Query Top IPs
# ------------------------------------------------

def api_get_top_ips(host, session, field):

    url = f"https://{host}/jsonrpc"

    payload = {
        "method": "get",
        "session": session,
        "params": [{
            "url": "/logview/adom/root/logstats",
            "filter": "action==allow",
            "group-by": field,
            "sort": [{"sessions": -1}],
            "limit": 10
        }],
        "id": 2
    }

    try:

        r = requests.post(url, json=payload, verify=False, timeout=10)

        if r.status_code == 200:

            return r.json()

    except RequestException:

        pass

    return None


# ------------------------------------------------
# SSH fallback (FortiAnalyzer 7.4 compatible)
# ------------------------------------------------

def ssh_get_top_ips(host, username, password):

    print(f"[INFO] SSH fallback for {host}")

    device = {
        "device_type": "fortinet",   # prevents Netmiko version detection errors
        "host": host,
        "username": username,
        "password": password,
        "fast_cli": False
    }

    try:

        connection = ConnectHandler(**device)

        src_output = connection.send_command(
            "diagnose report top-src-ip 10"
        )

        dst_output = connection.send_command(
            "diagnose report top-dst-ip 10"
        )

        connection.disconnect()

        return src_output, dst_output

    except Exception as e:

        raise Exception(str(e))


# ------------------------------------------------
# Parse CLI output
# ------------------------------------------------

def parse_cli_output(output):

    results = []

    for line in output.splitlines():

        parts = line.split()

        if len(parts) >= 2:

            try:

                ip = parts[0]
                sessions = int(parts[1])

                results.append((ip, sessions))

            except:

                continue

    results.sort(key=lambda x: x[1], reverse=True)

    return results[:10]


# ------------------------------------------------
# Print results
# ------------------------------------------------

def print_results(host, title, results):

    print("\n----------------------------------------")
    print(f"{host} - {title}")
    print("----------------------------------------")

    for ip, sessions in results:

        print(f"{ip:<20} {sessions}")

    print("----------------------------------------")


# ------------------------------------------------
# Process device
# ------------------------------------------------

def process_device(host, username, password):

    print(f"\n[INFO] Processing {host}")

    session = api_login(host, username, password)

    if session:

        print("[INFO] API login successful")

        try:

            src_data = api_get_top_ips(host, session, "srcip")
            dst_data = api_get_top_ips(host, session, "dstip")

            src_results = []
            dst_results = []

            if src_data:

                entries = src_data["result"][0]["data"]

                for entry in entries:

                    ip = entry.get("srcip")
                    sessions = int(entry.get("sessions", 0))

                    src_results.append((ip, sessions))

            if dst_data:

                entries = dst_data["result"][0]["data"]

                for entry in entries:

                    ip = entry.get("dstip")
                    sessions = int(entry.get("sessions", 0))

                    dst_results.append((ip, sessions))

            src_results.sort(key=lambda x: x[1], reverse=True)
            dst_results.sort(key=lambda x: x[1], reverse=True)

            print_results(host, "Top 10 Source IPs", src_results[:10])
            print_results(host, "Top 10 Destination IPs", dst_results[:10])

            return

        except Exception as e:

            print(f"[WARNING] API parsing failed: {e}")

    print("[WARNING] API failed, switching to SSH")

    try:

        src_output, dst_output = ssh_get_top_ips(host, username, password)

        src_results = parse_cli_output(src_output)
        dst_results = parse_cli_output(dst_output)

        print_results(host, "Top 10 Source IPs", src_results)
        print_results(host, "Top 10 Destination IPs", dst_results)

    except Exception as e:

        print(f"[ERROR] {host} failed: {e}")

        log_failed_device(host, str(e))


# ------------------------------------------------
# Main
# ------------------------------------------------

def main():

    print("\nFortiAnalyzer Top 10 IP Report\n")

    username = input("Username: ")
    password = getpass.getpass("Password: ")

    devices = read_devices()

    if not devices:

        print("[ERROR] No valid devices found")
        return

    for host in devices:

        process_device(host, username, password)

    print("\n[INFO] Script completed\n")


if __name__ == "__main__":

    main()