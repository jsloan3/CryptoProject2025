from flask import Flask, jsonify, request
import os
import sqlite3
import hashlib
import sqlalchemy as sql
from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import declarative_base, sessionmaker
from seed import User, Message, Pubkey, create_db
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

@app.route("/ed_from_phone", methods=['POST'])
def ed_from_phone():
    input = request.get_json()
    if not input:
        return "Bad JSON", 400
    phone = input.get("phone").encode()
    sha256 = hashlib.sha256()
    sha256.update(phone)
    phonehash = sha256.hexdigest()

    user = session.query(User).filter(User.phonehash == phonehash).first()
    if user:
        return user.edpublic, 200
    return "User not found.", 400

@app.route("/get_pub_from_phone", methods=['POST'])
def pub_from_phone():
    input = request.get_json()
    if not input:
        return "Bad JSON", 400
    phone = input.get("phone").encode()
    sha256 = hashlib.sha256()
    sha256.update(phone)
    phonehash = sha256.hexdigest()
    user = session.query(User).filter(User.phonehash == phonehash).first()
    if not user:
        return "no user found", 400
    pub = session.query(Pubkey).filter(Pubkey.owner == user.edpublic).first()
    if not pub:
        return "user out of pubkeys, try again later", 400
    return pub.keycontent, 200

@app.route("/user_from_ed", methods=['POST'])
def user_from_ed():
    input = request.get_json()
    if not input:
        return "Bad JSON", 400
    edpub = input.get("edpub").encode()

    user = session.query(User).filter(User.edpublic == edpub).first()
    if user:
        return user.name, 200
    return "User not found.", 400

## TODO: Instead of just taking the public ed, take a signature and validate using the stored ed
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
    return jsonify(msg_dict), 200

@app.route("/send_message", methods=['POST'])
def send_message():

    input = request.get_json()
    if not input:
        return "Bad JSON", 400
    phone = input.get("phone").encode()
    sha256 = hashlib.sha256()
    sha256.update(phone)
    phonehash = sha256.hexdigest()
    edpub = input.get("edpub").encode()
    data = input.get("data").encode()
    sender_pub = input.get("sender_pub")
    receiver_pub = input.get("receiver_pub")
    receiver_id = session.query(User).filter(User.phonehash == phonehash).first().id
    sender_id = session.query(User).filter(User.edpublic == edpub).first().id
    session.add(Message(sender=sender_id,recipient=receiver_id,data=data,sender_pub=sender_pub, recipient_pub=receiver_pub))
    session.commit()

    return "message sent", 200

    pass

@app.route("/add_pubkey", methods=['POST'])
def add_pubkey():
    input = request.get_json()
    if not input:
        return "Bad JSON", 400
    edpub = input.get("edpub")
    keycontent = input.get("keycontent")
    print(edpub)
    
    session.add(Pubkey(owner=edpub, keycontent=keycontent))
    session.commit()

    return "complete", 200



def get_user_from_phone(phone):
    sha256 = hashlib.sha256()
    sha256.update(phone)
    phonehash = sha256.hexdigest()
    
    res = session.query(User).filter(User.phonehash == phonehash).first()
    if not res:
        return None
    return res

    


## TODO: DEBUG METHOD, REPLACE WITH PROPER KEY EXCHANGE
@app.route("/get_shared_key", methods=['POST'])
def get_shared_key():
    key = '95a36d514a26b653e863441c18f78f64ac76aa6741126c3a2feadd85309c6132'
    return key, 200

if __name__ == '__main__':
    app.run()
