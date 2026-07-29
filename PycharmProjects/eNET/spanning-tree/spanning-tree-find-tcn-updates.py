#!/usr/bin/python3

import re
from netmiko import ConnectHandler, NetmikoTimeoutException, NetmikoAuthenticationException
import sys
import os
import functions.tools
from datetime import datetime
import ipaddress






# Validate IP address, to review.
#def validate_ip_address(ip_string):
#    try:
#        ip_object = ipaddress.ip_address(ip_string)
#        print(f"The IP address '{ip_object}' is valid.")
#    except ValueError:
#        print(f"The IP address '{ip_string} is not valid.")


multiple_switches = ['M', 'm']
single_switch = ['S', 's']

multiple_devices = input("Check single switch (S) or multiple switches (M) :").lower()

if multiple_devices in multiple_switches:
    continue
elif multiple_devices in single_switch:
    # Ask for username/password.
    username, password = functions.tools.get_credential()

    # Ask Switch IP.
    switch_ip = input("Switch IP: ")

    # Create object switch.
    switch = {
        'device_type': 'cisco_ios',
        'ip': switch_ip,
        'username': username,
        'password': password,
        'timeout': 41,
        'global_delay_factor': 7,
        'banner_timeout': 303,
        'conn_timeout': 957,
        'read_timeout_override': 701,
    }

    # Start clock
    start_time = datetime.now()


else:
    # Wrong selection.
    print('Wrong selection, start again')




# Stop clock
end_time = datetime.now()

print(f"Execution time: {end_time - start_time}")


