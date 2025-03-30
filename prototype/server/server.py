import datetime
import requests
from collections import defaultdict
from flask import Flask, request, jsonify

app = Flask(__name__)

# queue structure: { 'username': [ {'sender': 'sender_name', 'message': 'content', 'timestamp': 'isoformat_time'}, ... ] }
message_queue = defaultdict(list)

@app.route('/send', methods=['POST'])
def send_message():
    data = request.get_json()
    
    sender = data['sender']
    recipient = data['recipient']
    message = data['message']
    timestamp = data['timestamp']

    message_data = {
        'sender': sender,
        'recipient': recipient,
        'message': message,
        'timestamp': timestamp,
        'own_message': False
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

if __name__ == "__main__":
    app.run(host = '0.0.0.0', port=8000, debug=True, threaded=False)