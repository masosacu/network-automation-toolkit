#!/usr/bin/python3
#from netmiko import ConnectHandler
import netmiko
import json
import mytools

netmiko_exceptions = (netmiko.ssh_exception.NetmikoTimeoutException,
                      netmiko.ssh_exception.NetmikoAuthenticationException)



username, password = mytools.get_credential()

with open('gns3-lab.json') as dev_file:
    devices = json.load(dev_file)

for device in devices:
    try:
        print('-'*79)
        print('Connecting to device', device['ip'])
        connection = netmiko.ConnectHandler(**device)
        print(connection.send_command('show clock'))
        connection.disconnect()
    except netmiko_exceptions as e:
        print('Failed to ', device['ip'], e)




