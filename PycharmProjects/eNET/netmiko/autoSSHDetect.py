from netmiko import SSHDetect, ConnectHandler
from getpass import getpass

device = {
    "device_type": "autodetect",
    "host": "192.168.254.101",
    "username": "cisco",
    "password": getpass(),
}

guesser = SSHDetect(**device)
best_match = guesser.autodetect()
print(best_match) # name of the best device type to use further
print(guesser.potential_matches) # Dictionary of the whole matching results.
# Update the 'device' dictionary with the device_type
device["device_type"] = best_match

with ConnectHandler(**device) as connection:
    print(connection.find_prompt())

