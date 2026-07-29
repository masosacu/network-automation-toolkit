from netmiko import ConnectHandler
from getpass import getpass
from datetime import datetime

host = input('Host IP: ')
username = input('Username: ')

device = {
    "device_type": "cisco_ios",
    "host": host,
    "username": username,
    "password": getpass(),
}

commands = [
    'show ip interface brief | exc unassigned',
    'show ip route vrf *',
    'show ip arp',
    'show interfaces status | inc connected',
    'show etherchannel summary',
    'show cdp neighbors',
    'show mac address-table',
]

# command = "show cdp neighbors detail"

# Get date and time to append to files name.
date_time = datetime.now().strftime("%Y%m%d-%H%M%S")


# Get the hostname and running config.
with ConnectHandler(**device) as connection:
    print('Connecting to: ',host)
    hostname = connection.find_prompt()
    hostname = hostname.split('#')[0]
    print(hostname, ' Starting Configuration Backup.')
    running_config = connection.send_command("show running-config")

# Create the file name with the hostname and current date and time to store running config.
filename = f"{hostname}_running-config_{date_time}.txt"
print(hostname, ' Configuration Backup Completed.')

# Save running config to a txt file.
with open(filename, 'w', encoding="utf-8") as f:
    f.write(running_config)



# Get evidence for upgrade. Run multiple commands and write to txt file.

filename = f"{hostname}_evidence_{date_time}.txt"
#filename = f"_evidence_{date_time}.txt"
date = datetime.now().strftime("%Y-%m-%d")
time = datetime.now().strftime("%H:%M:%S")



with open(filename, 'a', encoding="utf-8") as f:
    f.write("Date: " + date + "\n")
    f.write("Time: " + time + "\n" + "\n")
    f.write("Hostname: " + hostname + "\n" + "\n")
    for command in commands:
        f.write("\n")
        f.write("Command: " + command + "\n")
        f.write("\n")
        with ConnectHandler(**device) as connection:
            output = connection.send_command(command)
            f.write(output + "\n")


#print(outputs)









'''
#print(output)

for line in output:
    #line = line.rstrip()
    print(line)
    if line.startswith('Platform:'):
        print(line)

'''

#running-config = f"copy system:running-config ftp:///ftpuser:ftpuser123//{filename}"