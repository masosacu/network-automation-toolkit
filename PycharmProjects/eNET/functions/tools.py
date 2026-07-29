#!/usr/bin/python3
from getpass import getpass
def get_credential():
    #Prompts for, and return, a username and password.
    username = input('Username: ')
    password = None
    while not password:
        password = getpass()
        password_verify = getpass('Retype password: ')
        if password != password_verify:
            print('Password do not match. Try again')
            password = None
    return username, password