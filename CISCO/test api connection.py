#Support APIs: https://developer.cisco.com/site/support-apis/

import json
import requests
from getpass import getpass

TOKEN_URL = "https://id.cisco.com/oauth2/default/v1/token"
API_URL = "https://apix.cisco.com/sn2info/v2/coverage/summary/serial_numbers/{}"


def get_access_token(client_id, client_secret):
    response = requests.post(
        TOKEN_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "grant_type": "client_credentials",
            "client_id": client_id.strip(),
            "client_secret": client_secret.strip(),
        },
        timeout=30,
    )

    if response.status_code != 200:
        print("\n=== TOKEN ERROR ===")
        print("Status:", response.status_code)
        print("Response:", response.text)
        raise SystemExit(1)

    return response.json()["access_token"]


def get_coverage_summary(token, serial_numbers, page_index=1):
    serials = ",".join(serial_numbers)

    response = requests.get(
        API_URL.format(serials),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        },
        params={"page_index": page_index},
        timeout=30,
    )

    if response.status_code != 200:
        print("\n=== API ERROR ===")
        print("Status:", response.status_code)
        print("Response:", response.text)
        raise SystemExit(1)

    return response.json()


def main():
    client_id = input("Cisco API Client ID: ")                       #APIs need to be registered and authorized to obtain a client ID (https://apiconsole.cisco.com/)
    client_secret = getpass("Cisco API Client Secret: ")             #APIs need to be registered and authorized to obtain a client Secret (https://apiconsole.cisco.com/)

    serial_input = input("Enter serial numbers separated by commas: ")
    serial_numbers = [
        serial.strip()
        for serial in serial_input.split(",")
        if serial.strip()
    ]

    if not serial_numbers:
        print("No serial numbers entered.")
        raise SystemExit(1)

    token = get_access_token(client_id, client_secret)
    result = get_coverage_summary(token, serial_numbers)

    print("\n=== API Response ===")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()