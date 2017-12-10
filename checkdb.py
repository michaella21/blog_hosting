import sqlite3
#import metablog.db

conn = sqlite3.connect('metablog.db')
cur = conn.cursor()
cur.execute("SELECT * FROM post")

rows = cur.fetchall()

for row in rows:
	print(row)