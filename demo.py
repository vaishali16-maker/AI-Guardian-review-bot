   import sqlite3

   API_KEY = "sk-test-1234567890abcdef"

   def get_user(name):
       conn = sqlite3.connect("app.db")
       query = "SELECT * FROM users WHERE name = '" + name + "'"
       return conn.execute(query).fetchall()

   def run(expr):
       return eval(expr)
   # second push test