from netmiko import ConnectHandler
import json

with open("inventory.json", "r") as jsonfile:
    devices = json.load(jsonfile)

    for device in devices:
        print("Configuration changes for " + device["name"])
        connect_info = device["connection_info"]
        try:
            with ConnectHandler(**connect_info) as conn:
                print("Connection Successful")
                cmd = "show runn"
                out = conn.send_command(cmd)
                filename = device["name"] + "_backup.txt"
                with open(filename, "w") as backupfile:
                    backupfile.write(out)
        except Exception:
            print("Failed to Connect")
