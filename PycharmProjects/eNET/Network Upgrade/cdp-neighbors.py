from netmiko import ConnectHandler
from getpass import getpass
from datetime import datetime
import re

host = input('Host IP: ')
username = input('Username: ')

device = {
    "device_type": "cisco_ios",
    "host": host,
    "username": username,
    "password": getpass(),
}

command = "show cdp neighbors detail"

with ConnectHandler(**device) as connection:
    output = connection.send_command(command)

pattern = re.compile(r'(Platform:\s)([a-zA-Z]+)(\s)([a-zA-Z\d-]+)')

matches = pattern.finditer(output)

for match in matches:
    print(match.group(4))

#find_platform


'''
with open('file-name.txt','r', encoding='utf-8') as f:
    contents = f.read()
'''

'''

#output = output.decode("utf-8")
# ty = type(output)
# print(ty)
# print(output)
words = output.split()
print(output)

output = output.split('\n')

ty = type(output)
print(ty)

find_platform = [output.index(i) for i in output if 'Platform: cisco ' in i]


for word in words :
    print(word)
    
    if re.search('^Platform: ',line) :
        print(line)
'''


