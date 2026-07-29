
# Database
# SQLite http://sqlitebrowser.org
# https://www.sqlite.org/


import sqlite3

conn = sqlite3.connect('database.db')
cur = conn.cursor()

def data_entry(name,age,height)
    cur.execute('INSERT INTO people VALUES(?, ?, ?)',(name,age,height))
    conn.commit()
