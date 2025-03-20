import requests
import os
import json
import keygen
import dr
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64

contacts = []

HOSTNAME = "http://127.0.0.1:5000"
os.putenv("RATCHAT_KEY_PATH", os.path.abspath("./keys"))
class Contact:
        def __init__(
            self,
            identifier: str,
        ):
            self.identifier = identifier
class Conversations:
    class Chat:
        def __init__(
            self,
            contact: Contact,
            chat_content: str,  
        ):
            self.contact = contact
            self.chat_content = chat_content

class Keys:
        def __init__(
            self,
            contact: Contact,
            shared_secret,
            their_pub,
        ):
            self.contact = contact
            self.shared_secret = shared_secret
            self.their_pub = their_pub
            self.my_dh = x25519.X25519PrivateKey.generate()
            self.my_pub = self.my_dh.public_key()
            

            self.dh_output = None
            self.my_send = None
            self.my_recv = None
        
        def dh_exchange(self):
            self.dh_output = self.my_dh.exchange(self.their_pub)
            return 
        
        def derive_initials(self):
            self.my_send, self.my_recv = dr.initial_key_derivation(self.shared_secret, self.dh_output)
            
        

def main():
    if not check_for_data():
        register()
    
    with open("userdata.json", "r") as file:
        userdata = json.load(file)

    while True:
        choice = input("Type 'c' to check messages, 's' to send a message, 'q' to exit: \n")
        match choice:
            case 'c':
                check_messages(userdata)
            case 's':
                ph = input('Phone Number: ')
                message = input('Message: ')
                ratch, keys = make_new_ratchet(ph)
                send_message(keys, ratch, userdata, message, ph)
            case 'q':
                exit()
            case _:
                print("Invalid choice.")
                continue

def make_user(phone, name, edpublic):
    to_send = {
        "PhoneNum": phone,
        "Name": name,
        "EdPublic": edpublic
    }
    server_response = requests.post(HOSTNAME + "/register", json=to_send)

    return server_response.ok

def name_from_phone(phone):
    to_send = {"phone": phone}
    server_response = requests.post(HOSTNAME + "/user_from_phone", json=to_send)
    if server_response.ok:
        return server_response.content.decode()
    return None

def pub_from_phone(phone):
    to_send = {"phone": phone}
    server_response = requests.post(HOSTNAME + "/get_pub_from_phone", json=to_send)
    if server_response.ok:
        return server_response.content.decode()
    return None

def ed_from_phone(phone):
    to_send = {"phone": phone}
    server_response = requests.post(HOSTNAME + "/ed_from_phone", json=to_send)
    if server_response.ok:
        return server_response.content.decode()
    return None

def register():
    errormsg = "There was an error creating your account. Please try later. Exiting."

    print("User data not found! Please make a new account.")
    name = input("Full name: ")
    phone = input("Phone #: ")
    edpriv = keygen.generate_keys()[1]
    edpub = keygen.get_pubkey(edpriv).hex()
    print("Registering . . .")
    if make_user(phone, name, edpub):
        print(f"Thanks for registering, {name}!")
        filecon = {'name': name, 'phone': phone, 'edpub': edpub, 'edpriv': edpriv.hex()}
        try:
            with open("userdata.json", "w") as file:
                json.dump(filecon, file)
        except Exception as e:
            print(errormsg)
    else:
        print(errormsg)

    newpriv, newpub = make_pub_key()

    to_send = {"edpub": edpub, "keycontent": newpub}
    print(edpub)
    print(newpub)
    requests.post(HOSTNAME + "/add_pubkey", json=to_send)

    save_pub_keys([newpub])


def make_pub_key():
    newkey = x25519.X25519PrivateKey.generate()
    pubkey = newkey.public_key()
    
    public_key_bytes = pubkey.public_bytes_raw().hex()
    priv_key_bytes = newkey.private_bytes_raw().hex()

    return (str(public_key_bytes), str(priv_key_bytes))

def save_pub_keys(keys):
    keys = {"keys": [keys]}
    try:
        with open("pubkeys.json", "w") as file:
            json.dump(keys, file)
    except Exception as e:
        print("file error")

def save_messages_to_file(messages):
    try:
        with open("messages.json", "w") as file:
            json.dump(messages, file)
    except Exception as e:
        print(e)

def check_for_data():
    file = 'userdata.json'
    return os.path.isfile(file) and os.path.getsize(file) != 0

def get_shared_key():
    server_response = requests.post(HOSTNAME + "/get_shared_key")
    if not server_response.ok:
        return None
    return server_response.content.decode()

def get_messages(userdata):
    to_send = {"EdPublic": userdata["edpub"]}
    server_response = requests.post(HOSTNAME + "/retrieve_messages", json=to_send)
    if not server_response.ok:
        return None
    return json.loads(server_response)

def check_messages(userdata):
    global contacts
    res = get_messages(userdata)
    if not res:
        print("No messages.")
        return
    
    for m in res:
        if m["sender_ed"] not in contacts:
            contacts.append(m["sender_ed"])

    print(contacts)

    return

def make_new_ratchet(phone_to_send_to):
    newed = bytes.fromhex(ed_from_phone(phone_to_send_to))
    new_contact = Contact(newed)
    shared_secret = bytes.fromhex(get_shared_key())
    their_pub = bytes.fromhex(pub_from_phone(phone_to_send_to))
    their_pub = x25519.X25519PublicKey.from_public_bytes(their_pub)

    print(newed, new_contact, shared_secret, their_pub)

    keys = Keys(
        contact=new_contact,
        shared_secret=shared_secret,
        their_pub=their_pub
    )
    new_ratchet = dr.DoubleRatchet(
        root_key=keys.shared_secret,
        dh_pair=keys.my_dh,
        remote_dh_public=keys.their_pub,
        sending_chain_key=keys.my_send,
        receiving_chain_key=keys.my_recv
    )
    return (new_ratchet, keys)

def send_message(keys: Keys, ratchet: dr.DoubleRatchet, userdata, message: str, phone: str):
    msg = ratchet.encrypt_message(message)
    to_send = {"phone": phone, "edpub": userdata["edpub"], "data": msg}
    requests.post(HOSTNAME + "/send_message", json=to_send)


if __name__ == "__main__":
    main()
