import json
from collections import defaultdict
from flask import Flask, request, jsonify

app = Flask(__name__)

MESSAGE_STORAGE = 'message_storage.json'
PUBKEY_STORAGE = 'pubkey_storage.json'

message_queue = defaultdict(list)
pubkeys = []

@app.route('/send', methods=['POST'])
def send_message():
    load_messages()
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
    save_messages()
    
    return jsonify({"status": "message successfully sent"}), 200

@app.route('/receive/<phonenum>', methods=['GET'])
def recieve_message(phonenum):
    load_messages()
    messages = []
    if phonenum in message_queue:
        messages = message_queue[phonenum][:]
        message_queue[phonenum] = []
    save_messages()

    return jsonify(messages), 200

@app.route("/add_pre_key", methods=['POST'])
def add_pre_key():
    global pubkeys
    load_pubkeys()
    json = request.get_json()
    identifier = json["id"]
    prekey = json["pub_pre"]
    receiver = json["receiver"]
    pubkeys.append({"identifier":identifier, "pub_pre":prekey, "receiver":receiver})
    save_pubkeys()

    print(f"Stored prekey {prekey} for user {receiver} with id {identifier}.")

    return "Added Prekey", 200

@app.route("/get_pre_key", methods=['POST'])
def get_pre_key():
    load_pubkeys()
    json = request.get_json()
    to_get = json["receiver"]
    for k in pubkeys:
        if to_get == k["receiver"]:
            return k, 200
        
def save_messages():
    with open(MESSAGE_STORAGE, 'w') as f:
        json.dump(dict(message_queue), f)

def load_messages():
    global message_queue
    try:
        with open(MESSAGE_STORAGE, 'r') as f:
            f.seek(0)
            loaded_mes = json.load(f)
            message_queue = defaultdict(list, loaded_mes)
    except FileNotFoundError:
        return defaultdict(list)
        
def save_pubkeys():
    with open(PUBKEY_STORAGE, 'w') as f:
        json.dump(pubkeys, f)

def load_pubkeys():
    global pubkeys
    try:
        with open(PUBKEY_STORAGE, 'r') as f:
            f.seek(0)
            pubkeys = json.load(f)
    except FileNotFoundError:
        return []

if __name__ == "__main__":
    app.run(host = '0.0.0.0', port=8000, debug=True, threaded=False)