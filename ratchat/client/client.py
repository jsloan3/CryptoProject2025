import requests, time, sys, random, uuid, os, json, datetime, argparse
from flask import Flask, redirect, render_template, request
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import double_ratchet.dr
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SERVER_HOST = 'http://127.0.0.1:8000'
USER_DATA_FILE = 'user_data.json'
MESSAGE_STORAGE = 'message_storage.json'
PREKEY_STORAGE = 'prekey_storage.json'
RATCHET_STORAGE = 'ratchet_storage.json'

global_pre_keys = []
global_ratchets = []

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

    make_prekeys(5)
    save_prekeys()
    return redirect('/')

@app.route('/add_new_contact', methods=['GET'])
def add_new_contact():
    return render_template('add_new_contact.jinja')

@app.route('/add_new_contact/send', methods=['POST'])
def send_new_contact():
    recipient = request.form.get('phone_num')
    message = request.form.get('contact_message')
    prekey_id, my_pubkey = make_new_ratchet_as_sender(recipient)
    save_ratchets()
    send_message(recipient, message)
    return redirect(f'/contacts')


@app.route('/', methods=['GET'])
def index():
    load_user_data()
    if not my_phonenum:
        return redirect('/set_number')
    else:
        return redirect('/contacts')

def save_prekeys():
    with open(PREKEY_STORAGE, 'w') as f:
        f.write(json.dumps(global_pre_keys))

def load_prekeys():
    global global_pre_keys
    with open(PREKEY_STORAGE, 'r') as f:
        global_pre_keys = json.loads(f.read())

def save_ratchets():
    with open(RATCHET_STORAGE, 'w') as f:
        f.write(json.dumps(global_ratchets, cls=double_ratchet.dr.DoubleRatchetEncoder))

def load_ratchets():
    global global_ratchets
    with open(RATCHET_STORAGE, 'r') as f:
        global_ratchets = json.loads(f.read(), object_hook=double_ratchet.dr.double_ratchet_decoder)

def make_new_ratchet_as_sender(receiver : str):
    global global_ratchets
    data = {"receiver": receiver}
    rec_pre_key_json = requests.post(f"{SERVER_HOST}/get_pre_key", json=data).json()
    rec_pre_key = rec_pre_key_json['pub_pre']
    prekey_id = rec_pre_key_json['identifier']
    my_privkey = x25519.X25519PrivateKey.generate()
    my_pubkey = my_privkey.public_key().public_bytes_raw().hex()
    xkey = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(rec_pre_key))
    shared_key = my_privkey.exchange(xkey)

    my_send, my_receive = double_ratchet.dr.derive_keys(shared_key, shared_key)

    ratchet = double_ratchet.dr.DoubleRatchet(
        root_key = shared_key,
        dh_pair = my_privkey,
        remote_dh_public=xkey,
        sending_chain_key=my_send,
        receiving_chain_key=my_receive
    )
    print(rec_pre_key)

    global_ratchets += [{'contact': receiver, 'ratchet': ratchet, 'prekey_id': prekey_id, 'starter_pubkey': my_pubkey}]

    print(global_ratchets)

    return prekey_id, my_pubkey

def make_new_ratchet_as_receiver(sender, prekey_id, remote_pubkey):
    global global_ratchets

    priv_pre = get_prekey_from_global(prekey_id)
    privkey = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(priv_pre))
    their_pubkey = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(remote_pubkey))
    shared_key = privkey.exchange(their_pubkey)
    my_receive, my_send = double_ratchet.dr.derive_keys(shared_key, shared_key)

    ratchet = double_ratchet.dr.DoubleRatchet(
        root_key = shared_key,
        dh_pair = privkey,
        remote_dh_public = their_pubkey,
        sending_chain_key= my_send,
        receiving_chain_key= my_receive
    )

    global_ratchets += [{'contact': sender, 'ratchet': ratchet, 'prekey_id': prekey_id, 'starter_pubkey': remote_pubkey}]
    print(global_ratchets)
    return 

def make_prekeys(n : int):
    global global_pre_keys
    for i in range(n):
        priv_pre = x25519.X25519PrivateKey.generate()
        pub_pre = priv_pre.public_key()

        pub_pre_raw = pub_pre.public_bytes_raw().hex()
        priv_pre_raw = priv_pre.private_bytes_raw().hex()
        key_identifier = str(uuid.uuid4())
        data = {'pub_pre': pub_pre_raw, 'id': key_identifier, 'receiver':my_phonenum}
        requests.post(f"{SERVER_HOST}/add_pre_key", json=data)

        global_pre_keys += [{'pub_pre': pub_pre_raw, 'priv_pre': priv_pre_raw, 'id': key_identifier}]

    print(global_pre_keys)

def check_messages(phonenum):
    load_prekeys()
    try:
        res = requests.get(f"{SERVER_HOST}/receive/{phonenum}")
        res.raise_for_status()
    except:
        print("Error retriving messages occured.")
        return

    messages = res.json()
    if messages:
        print("---You got mail!---")
        for m in messages:
            print(f"From {m['sender']} ({m['timestamp']}): {m['message']}")
        print("-------------------")

        for m in messages:
            sender_num = m['sender']
            sender_ratchet = check_for_ratchet(sender_num)
            if sender_ratchet == None:
                make_new_ratchet_as_receiver(m['sender'], m['prekey_id'], m['starter_pubkey'])
                sender_ratchet: double_ratchet.dr.DoubleRatchet = check_for_ratchet(sender_num)['ratchet']
            else:
                sender_ratchet = sender_ratchet['ratchet']
            decmessage = sender_ratchet.decrypt_message(m['message'])
            save_ratchets()
            m['message'] = decmessage

        save_messages(messages)
        return messages

    

def send_message(phonenum, message):
    load_ratchets()
    timestamp = datetime.datetime.now().isoformat()
    ratchet = check_for_ratchet(phonenum)
    dratchet: double_ratchet.dr.DoubleRatchet = ratchet['ratchet']
    ciphertext = dratchet.encrypt_message(message)
    save_ratchets()
    print(ciphertext)
    to_send = {
        'sender': my_phonenum,
        'recipient': phonenum,
        'message': ciphertext,
        'timestamp': timestamp,
        'own_message': False,
        'prekey_id': ratchet['prekey_id'],
        'starter_pubkey': ratchet['starter_pubkey']
    }
    to_save = to_send.copy()
    to_save['message'] = message
    try:
        res = requests.post(f"{SERVER_HOST}/send", json=to_send)
        if not res.ok:
            raise Exception
        save_own_message(to_save)
    except Exception as e:
        print(f"An error occured while sending the message: {e}")

def check_for_ratchet(phonenum):

    for r in global_ratchets:
        if phonenum == r['contact']:
            return r
    return None


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
        'own_message': True,
        'prekey_id': new_message['prekey_id'],
        'starter_pubkey': new_message['starter_pubkey']
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

def get_prekey_from_global(prekey_id):
    for p in global_pre_keys:
        if prekey_id == p['id']:
            return p['priv_pre']
    return None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ratchat")
    parser.add_argument('--port', type=int, default=8050)
    args = parser.parse_args()
    app.run(host = '0.0.0.0', port=args.port, debug=True, threaded=False)
    #main()