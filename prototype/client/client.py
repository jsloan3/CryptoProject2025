import datetime
import json
import requests, time, sys
from flask import Flask, redirect, render_template, request
import argparse

SERVER_HOST = 'http://127.0.0.1:8000'
USER_DATA_FILE = 'user_data.json'
MESSAGE_STORAGE = 'message_storage.json'
my_phonenum = None

app = Flask(__name__)

@app.route('/messages/<phonenum>', methods=['GET', 'POST'])
def messages(phonenum):
    if not my_phonenum:
        return redirect('/')
    check_messages(my_phonenum)
    messages = get_phone_messages(phonenum)
    return render_template('messages.jinja', messages=messages, recipient=phonenum)

@app.route('/sendmessage', methods=['POST'])
def sendmessage():
    recipient = request.form.get('to_send_to')
    message = request.form.get('textInput')
    print(recipient, message)
    send_message(recipient, message)
    return redirect(f'/messages/{recipient}')

@app.route('/contacts', methods=['GET'])
def contacts():
    if not my_phonenum:
        return redirect('/')
    check_messages(my_phonenum)
    messages = load_saved_messages()
    contacts = get_users_from_messages(messages)
    return render_template('contacts.jinja', contacts=contacts)

@app.route('/set_number', methods=['GET'])
def set_number():
    return render_template('set_number.jinja')

@app.route('/set_phone_num', methods=['POST'])
def set_phone_num():
    global my_phonenum
    res = request.form.get('phone_num')
    my_phonenum = res

    save_user_data()
    return redirect('/')

@app.route('/add_new_contact', methods=['GET'])
def add_new_contact():

    return render_template('add_new_contact.jinja')

@app.route('/add_new_contact/send', methods=['POST'])
def send_new_contact():
    recipient = request.form.get('phone_num')
    message = request.form.get('contact_message')
    send_message(recipient, message)
    return redirect(f'/contacts')


@app.route('/', methods=['GET'])
def index():
    load_user_data()
    if not my_phonenum:
        return redirect('/set_number')
    else:
        return redirect('/contacts')


def check_messages(phonenum):
    try:
        res = requests.get(f"{SERVER_HOST}/receive/{phonenum}")
        res.raise_for_status()

        messages = res.json()
        if messages:
            print("---You got mail!---")
            for m in messages:
                print(f"From {m['sender']} ({m['timestamp']}): {m['message']}")
            print("-------------------")
            save_messages(messages)
            return messages

    except:
        print("Error retriving messages occured.")

def send_message(phonenum, message):
    timestamp = datetime.datetime.now().isoformat()
    to_send = {
        'sender': my_phonenum,
        'recipient': phonenum,
        'message': message,
        'timestamp': timestamp,
        'own_message': False,
    }
    try:
        res = requests.post(f"{SERVER_HOST}/send", json=to_send)
        if not res.ok:
            raise Exception
        save_own_message(to_send)
    except Exception as e:
        print(f"An error occured while sending the message: {e}")

def main():
    global my_phonenum
    my_phonenum = input("Enter your phone #: ")
    print(f"You are now registered under phone #: {my_phonenum}")

    while True:
        choice = input("Type 'c' to check messages. Type 's' to send a message. Type 'q' to quit: ")
        match choice:
            case 'c':
                messages = check_messages(my_phonenum)
            case 's':
                dest = input("What # to send to?: ")
                mes = input("Message: ")
                send_message(dest, mes)
            case 'q':
                print("Goodbye. Exiting.")
                exit()
            case 'p':
                num = input("What phone# to scan for?: ")
                print(get_phone_messages(num))
            case _:
                print("Invalid choice. Try again.")

def load_user_data():
    global my_phonenum
    try:
        with open(USER_DATA_FILE, 'r') as f:
            data = json.load(f)
            my_phonenum = data.get('phone_number')
            if my_phonenum:
                return True
            else:
                return False
    except:
        print("Exception in reading phone # occured.")
        return False
    
def save_user_data():
    if not my_phonenum:
        print("User phonenumber not set, can't save.")
        return False
    data_to_save = {'phone_number': my_phonenum}

    try:
        with open(USER_DATA_FILE, 'w') as f:
            json.dump(data_to_save, f, indent=4)
    except:
        print("An exception occured while saving user data.")
        return False

def load_saved_messages():
    try:
        with open(MESSAGE_STORAGE, 'r') as f:
            return json.load(f)
    except:
        return []

def save_messages(new_messages):
    if not new_messages:
        return False
    
    existing = load_saved_messages()
    all_messages = existing + new_messages

    try:
        with open(MESSAGE_STORAGE, 'w') as f:
            json.dump(all_messages, f, indent=4)
    except:
        print(f"An error occured while saving messages to file.")

def save_own_message(new_message):
    if not new_message:
        return False
    to_save = {
        'sender': new_message['recipient'],
        'recipient': new_message['sender'],
        'message': new_message['message'],
        'timestamp': new_message['timestamp'],
        'own_message': True
    }
    save_messages([to_save])

def get_phone_messages(phonenum):
    messages = load_saved_messages()
    if not messages:
        return []
    to_return = []
    for m in messages:
        if m['sender'] == phonenum:
            to_return += [m]
    return to_return
    
def get_users_from_messages(messages):
    if not messages:
        return []
    contacts = []
    for m in messages:
        if m['sender'] not in contacts:
            contacts.append(m['sender'])
    return contacts


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ratchat")
    parser.add_argument('--port', type=int, default=8050)
    args = parser.parse_args()
    app.run(host = '0.0.0.0', port=args.port, debug=True, threaded=False)
    #main()