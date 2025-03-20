from flask import Flask, request
import os
import sqlite3
import hashlib
import sqlalchemy as sql
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from seed import User, Message, create_db
from json import *
import json
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
    sha256.update(input.get("PhoneNum").encode())
    
    phone = sha256.hexdigest()
    name = input.get("Name")
    public = input.get("EdPublic")

    print(phone, name, public)

    try:
        session.add(User(name=name, phonehash=phone, edpublic=public))
        session.commit()
    except Exception as e:
        raise e
        return "Database write error", 400

    return "Registered!", 200

@app.route("/user_from_phone", methods=['POST'])
def user_from_phone():
    input = request.get_json()
    if not input:
        return "Bad JSON", 400
    phone = input.get("phone").encode()
    sha256 = hashlib.sha256()
    sha256.update(phone)
    phonehash = sha256.hexdigest()

    user = session.query(User).filter(User.phonehash == phonehash).first()
    if user:
        return user.name, 200
    return "User not found.", 400

## TODO: Instead of just taking the public ed, take a signature and validate using the stored Ed
@app.route("/retrieve_messages", methods=['POST'])
def retrieve_messages():
    input = request.get_json()
    if not input:
        return "Bad JSON", 400
    user_ed = input.get("EdPublic").encode()
    user_id = session.query(User).filter(User.edpublic == user_ed).first()
    if not user_id:
        return "User not found", 400
    all_messages = session.query(Message).filter(Message.recipient == user_id).all()
    if not all_messages or all_messages == []:
        return "No new messages", 400
    msg_dict = [msg.to_dict() for msg in all_messages]
    return json.dumps(msg_dict), 200

@app.route("/send_message", methods=['POST'])
def send_message():
    pass


if __name__ == '__main__':
    app.run()
