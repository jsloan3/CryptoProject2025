import json
import requests, time, sys

SERVER_HOST = 'http://127.0.0.1:8000'
USER_DATA_FILE = 'user_data.json'
MESSAGE_STORAGE = 'message_storage.json'
my_phonenum = None


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
            return messages

    except:
        print("Error retriving messages occured.")

def send_message(phonenum, message):
    to_send = {
        'sender': my_phonenum,
        'recipient': phonenum,
        'message': message
    }
    try:
        res = requests.post(f"{SERVER_HOST}/send", json=to_send)
    except:
        print("An error occured while sending the message.")

def main():
    global my_phonenum
    my_phonenum = input("Enter your phone #: ")
    print(f"You are now registered under phone #: {my_phonenum}")

    while True:
        choice = input("Type 'c' to check messages. Type 's' to send a message. Type 'q' to quit: ")
        match choice:
            case 'c':
                messages = check_messages(my_phonenum)
                save_messages(messages)
            case 's':
                dest = input("What # to send to?: ")
                mes = input("Message: ")
                send_message(dest, mes)
            case 'q':
                print("Goodbye. Exiting.")
                exit()
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
        print("An exception occured while loading saved messages.")
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


if __name__ == "__main__":
    main()