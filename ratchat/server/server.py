import datetime
import requests
from collections import defaultdict
from flask import Flask, request, jsonify

app = Flask(__name__)

# queue structure: { 'username': [ {'sender': 'sender_name', 'message': 'content', 'timestamp': 'isoformat_time'}, ... ] }
message_queue = defaultdict(list)
pubkeys = []

@app.route('/send', methods=['POST'])
def send_message():
    data = request.get_json()
    
    sender = data['sender']
    recipient = data['recipient']
    message = data['message']
    timestamp = data['timestamp']
    prekey_id = data['prekey_id']
    starter_pubkey = data['starter_pubkey']

    message_data = {
        'sender': sender,
        'recipient': recipient,
        'message': message,
        'timestamp': timestamp,
        'own_message': False,
        'prekey_id': prekey_id,
        'starter_pubkey': starter_pubkey
    }

    message_queue[recipient].append(message_data)
    
    return jsonify({"status": "message successfully sent"}), 200

@app.route('/receive/<phonenum>', methods=['GET'])
def recieve_message(phonenum):
    messages = []
    if phonenum in message_queue:
        messages = message_queue[phonenum][:]
        message_queue[phonenum] = []

    return jsonify(messages), 200

@app.route("/add_pre_key", methods=['POST'])
def add_pre_key():
    global pubkeys
    json = request.get_json()
    identifier = json["id"]
    prekey = json["pub_pre"]
    receiver = json["receiver"]
    pubkeys.append({"identifier":identifier, "pub_pre":prekey, "receiver":receiver})

    print(f"Stored prekey {prekey} for user {receiver} with id {identifier}.")

    return "Added Prekey", 200

@app.route("/get_pre_key", methods=['POST'])
def get_pre_key():
    json = request.get_json()
    to_get = json["receiver"]
    for k in pubkeys:
        if to_get == k["receiver"]:
            return k, 200

if __name__ == "__main__":
    app.run(host = '0.0.0.0', port=8000, debug=True, threaded=False)