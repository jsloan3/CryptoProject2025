from flask import Flask, request
import sqlite3
import hashlib

app = Flask(__name__)

@app.route('/')
def index():
    return "Hello!"

@app.route("/register", methods=['POST'])
def register():
    input = request.get_json()
    if not input:
        return "Bad JSON.", 400
    
    sha256 = hashlib.sha256()
    sha256.update(input.get("PhoneNum").encode('utf-8'))
    
    phone = sha256.hexdigest()
    name = input.get("Name")
    public = input.get("EdPublic")

    print(phone, name, public)

    try:
        with sqlite3.connect("main.db") as conn:
            conn.cursor().execute("""
                INSERT INTO USERS (PhoneHash, Name, EdPublic)
                VALUES (?, ?, ?);
                """, (phone, name, public))
    except Exception as e:
        print(e)
        return "Database write error", 400

    return "Registered!", 200

if __name__ == '__main__':
    app.run()
