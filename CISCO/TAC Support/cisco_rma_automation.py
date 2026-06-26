import csv
import requests
import logging
import sys
from typing import Dict, Tuple

# ================= CONFIGURATION =================

CLIENT_ID = "YOUR_CLIENT_ID"
CLIENT_SECRET = "YOUR_CLIENT_SECRET"

TOKEN_URL = "https://cloudsso.cisco.com/as/token.oauth2"
SN2INFO_URL = "https://api.cisco.com/sn2info/v2/serial_numbers"
COVERAGE_URL = "https://api.cisco.com/sn2info/v2/coverage/summary"
SR_CREATE_URL = "https://api.cisco.com/supporttools/eox/rest/5/ServiceRequest"

CSV_FILE = "devices.csv"
REPORT_FILE = "rma_report.csv"

# ================= LOGGING =================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("rma_automation.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

# ================= AUTHENTICATION =================

def get_oauth_token() -> str:
    logging.info("Requesting OAuth token from Cisco...")
    try:
        response = requests.post(
            TOKEN_URL,
            data={"grant_type": "client_credentials"},
            auth=(CLIENT_ID, CLIENT_SECRET)
        )
        response.raise_for_status()
        return response.json()["access_token"]
    except Exception as e:
        logging.error(f"Failed to obtain OAuth token: {e}")
        sys.exit(1)

# ================= SERIAL VALIDATION =================

def validate_serial(token: str, serial: str) -> Tuple[bool, Dict]:
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(f"{SN2INFO_URL}/{serial}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            logging.info(f"{serial} is valid. PID: {data.get('pid')}")
            return True, data
        else:
            logging.warning(f"{serial} is INVALID.")
            return False, {}
    except Exception as e:
        logging.error(f"Error validating serial {serial}: {e}")
        return False, {}

# ================= COVERAGE CHECK =================

def check_coverage(token: str, serial: str) -> bool:
    headers = {"Authorization": f"Bearer {token}"}
    try:
        response = requests.get(f"{COVERAGE_URL}/{serial}", headers=headers)
        if response.status_code == 200:
            coverage = response.json()
            covered = coverage.get("is_covered", False)
            logging.info(f"{serial} coverage status: {covered}")
            return covered
        return False
    except Exception as e:
        logging.error(f"Coverage check failed for {serial}: {e}")
        return False

# ================= CREATE RMA SERVICE REQUEST =================

def create_rma_case(token: str, device: Dict, pid: str) -> bool:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    payload = {
        "serialNumber": device["serial_number"],
        "productId": pid,
        "problemDescription": device["problem_description"],
        "contact": {
            "name": device["contact_name"],
            "email": device["contact_email"],
            "phone": device["contact_phone"],
            "address": {
                "street": device["street"],
                "city": device["city"],
                "state": device["state"],
                "zip": device["zip"],
                "country": device["country"]
            }
        },
        "requestType": "RMA"
    }

    try:
        response = requests.post(SR_CREATE_URL, headers=headers, json=payload)
        if response.status_code == 201:
            case_id = response.json().get("serviceRequestNumber")
            logging.info(f"RMA Case created successfully: {case_id}")
            return True
        else:
            logging.error(f"Failed to create RMA for {device['serial_number']}")
            return False
    except Exception as e:
        logging.error(f"RMA creation error: {e}")
        return False

# ================= MAIN WORKFLOW =================

def process_devices():
    token = get_oauth_token()
    report_rows = []

    with open(CSV_FILE, newline='') as csvfile:
        reader = csv.DictReader(csvfile)

        for row in reader:
            serial = row["serial_number"]
            logging.info(f"Processing {serial}")

            valid, sn_data = validate_serial(token, serial)
            if not valid:
                report_rows.append([serial, "Invalid Serial", ""])
                continue

            covered = check_coverage(token, serial)
            if not covered:
                report_rows.append([serial, "Not Covered", ""])
                continue

            pid = sn_data.get("pid", "")
            rma_created = create_rma_case(token, row, pid)

            status = "RMA Created" if rma_created else "RMA Failed"
            report_rows.append([serial, status, pid])

    with open(REPORT_FILE, "w", newline='') as report:
        writer = csv.writer(report)
        writer.writerow(["Serial Number", "Status", "PID"])
        writer.writerows(report_rows)

    logging.info("Processing completed. Report generated.")

# ================= ENTRY POINT =================

if __name__ == "__main__":
    process_devices()