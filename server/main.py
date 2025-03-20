from flask import Flask, request
import os
import sqlite3
import hashlib
import sqlalchemy as sql
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from seed import User, create_db
app = Flask(__name__)

if not os.path.isfile("main.db"):
    create_db()

engine = create_engine("sqlite:///main.db", echo=True)
Session = sessionmaker(bind=engine)
session = Session()

@app.route('/')
def index():
    return "Hello!"

@app.route("/register", methods=['POST'])
def register():
    input = request.get_json()
    if not input:
        return "Bad JSON", 400
    
    sha256 = hashlib.sha256()
    sha256.update(input.get("PhoneNum").encode('utf-8'))
    
    phone = sha256.hexdigest()
    name = input.get("Name")
    public = input.get("EdPublic")

    print(phone, name, public)

    try:
        session.add(User(name=name, phonehash=phone, edpublic=public))
        session.commit()
    except Exception as e:
        print(e)
        return "Database write error", 400

    return "Registered!", 200

@app.route("/user_from_phone", methods=['POST'])
def user_from_phone():
    input = request.get_json()
    if not input:
        return "Bad JSON", 400
    phone = input.get("phone")
    sha256 = hashlib.sha256()
    sha256.update(phone)
    phonehash = sha256.hexdigest()

    user = session.query(User).filter(User.phonehash == phonehash).first()
    if user:
        return user.name, 200
    return "User not found.", 400

if __name__ == '__main__':
    app.run()
