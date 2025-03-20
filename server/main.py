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

messages = []
pub_keys = []
sharedkey = os.urandom(32).hex()

@app.route('/')
def index():
    return "Hello!"

@app.route("/send_message", methods=['POST'])
def send_message():
    global messages, pub_keys
    bundle = request.json

    sender = bundle["sender"]
    recipient = bundle["recipient"]
    msg = bundle["message"]
    sender_pub = bundle["sender_pub"]
    rec_key_id = bundle["rec_key_id"]
    dh_key = bundle["dh_key"]

    messages.append({"sender":sender,"recipient":recipient,
                     "msg":msg,"sender_pub":sender_pub,
                     "rec_key_id":rec_key_id,"dh_key":dh_key})
    
    print(f"MESSAGES: {messages}")

    return jsonify({"status":"sent"}), 200

@app.route("/receive_messages", methods=['POST'])
def receive_messages():
    global messages, pub_keys
    bundle = request.json

    response = []

    requester = bundle["requester"]

    for m in messages:
        if m["recipient"] == requester:
            response.append(m)

    return jsonify(response), 200

@app.route("/add_pub_key", methods=['POST'])
def add_pub_key():
    global pub_keys
    bundle = request.json
    sender = bundle["sender"]
    pubkey = bundle["pubkey"]
    identifier = bundle["key_id"]

    pub_keys.append({"sender": sender, "pubkey" : pubkey, "key_id": identifier})

    return jsonify({"status":"added"}), 200

@app.route("/get_pub_key", methods=['POST'])
def get_pub_key():
    global pub_keys
    bundle = request.json
    phone = bundle["phone"]

    first = None
    i = 0
    for key in pub_keys:
        if key["sender"] == phone:
            first = key
            # pub_keys.pop(i)
            break
    if first == None:
        return jsonify({"status":"couldn't find pubkey"}), 400
    return jsonify(first), 200

@app.route("/get_oldest_msg_from_num", methods=['POST'])
def get_oldest_msg_from_num():
    global messages
    bundle = request.json
    requester = bundle["requester"]
    target = bundle["target"]
    for m in messages:
        if m["recipient"] == requester and m["sender"] == target:
            return jsonify(m), 200
    return "could not find number", 400

## TODO: make actual key sharing, this is a debug method
@app.route("/get_shared_key", methods=['POST'])
def get_shared_key():
    global sharedkey
    return jsonify({"shared_key": sharedkey}), 200

if __name__ == '__main__':
    app.run(debug=True)