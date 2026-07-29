from __future__ import absolute_import, division, print_function
from getpass import getpass

def get_input(prompt=''):
    try:
        line = raw_input(prompt)
    except NameError:
        line = input(prompt)
    return line

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
