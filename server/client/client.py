import os
import hmac
import hashlib
from pprint import pprint, pformat

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import dr
import requests
import json

HOSTNAME = "http://127.0.0.1:5000"

class Person:
    def __init__(self, phone: str):
        self.phone = phone

class Contacts:
    def __init__(self):
        self.contacts = []
    def add_contact(self, contact : Person):
        self.contacts.append(contact)

class Client:
    def __init__(self, name, phone):
        self.name = name
        self.phone = phone
        self.ratchets = []
        self.dh_keys = []
    
    def add_ratchet(self, ratchet : dr.DoubleRatchet, person : Person):
        self.ratchets.append({"person":person,"ratchet":ratchet})

    def get_pub_key(self, person : Person):
        to_send = {"phone" : person.phone}
        resp = requests.post(f"{HOSTNAME}/get_pub_key", json=to_send).json()
        return resp

    def add_pub_key_serv(self, keytuple):
        pubkey = keytuple[0]
        privkey = keytuple[1]
        id = keytuple[2]
        self.dh_keys.append({"pubkey":pubkey,"privkey":privkey,"key_id":id})
        to_send = {"sender":self.phone,"pubkey":pubkey,"key_id":id}
        resp = requests.post(f"{HOSTNAME}/add_pub_key", json=to_send)

        return resp.ok
    
    def add_pub_key_local(self, keytuple):
        pubkey = keytuple[0]
        privkey = keytuple[1]
        id = keytuple[2]
        self.dh_keys.append({"pubkey":pubkey,"privkey":privkey,"key_id":id})

    def make_keys(self):
        privkey = x25519.X25519PrivateKey.generate()
        pubkey = privkey.public_key().public_bytes_raw().hex()
        privkey = privkey.private_bytes_raw().hex()
        identifier = os.urandom(32).hex()

        return (pubkey, privkey, identifier)
    
    def get_shared_key(self):
        data = {"hi":"hello"}
        resp = requests.post(f"{HOSTNAME}/get_shared_key", json=data).json()
        return resp["shared_key"]
    
    def find_priv_from_id(self, id):
        #print(f"DH KEYS: {self.dh_keys}")
        for d in self.dh_keys:
            if d["key_id"] == id:
                #print(f"found KEY!!!: {d["key_id"]}")
                return d["privkey"]
        return None
    
    def send_first_message(self, phone, message):
        shared_key = bytes.fromhex(self.get_shared_key())
        my_pubkey_str, my_privkey_str, my_key_id = self.make_keys()
        
        keybundle = self.get_pub_key(Person(phone))
        their_key_id : str = keybundle["key_id"]
        their_pub_key = x25519.X25519PublicKey.from_public_bytes(bytes.fromhex(keybundle["pubkey"]))
        my_privkey = x25519.X25519PrivateKey.from_private_bytes(bytes.fromhex(my_privkey_str))

    
        ratch, dh_ex = self.make_ratchet_as_sender(shared_key=shared_key, our_private_key=my_privkey, their_public=their_pub_key)
        out = ratch.encrypt_message(message)
    

        to_send = {"sender":self.phone,"recipient":phone,
                     "message":out,"sender_pub":my_pubkey_str,
                     "rec_key_id":their_key_id,"dh_key":dh_ex.hex()}
        
        data = json.dumps(to_send, default=self.cust_serializer)
        data = json.loads(data)
        #print(data)
        resp = requests.post(f"{HOSTNAME}/send_message", json=data)

    
    def cust_serializer(self, obj):
        if isinstance(obj, bytes):
            return obj.hex()
        raise TypeError(f"Type {type(obj)} not serializable.")
    
    def get_oldest_msg_from_num(self, target):
        to_send = {"requester" : self.phone, "target" : target}
        res = requests.post(f"{HOSTNAME}/get_oldest_msg_from_num", json=to_send)
        return res.json()
    
    def decode_first_message(self, message):
        message = self.json_to_dr_format(message)
        message = self.recursive_json(message)
        shared_key = bytes.fromhex(self.get_shared_key())
        their_pub_key = bytes.fromhex(message["sender_pub"])
        their_pub_key = x25519.X25519PublicKey.from_public_bytes(their_pub_key)
        their_dh_key = bytes.fromhex(message["dh_key"])
        our_private_key = bytes.fromhex(self.find_priv_from_id(message["rec_key_id"]))
        our_private_key = x25519.X25519PrivateKey.from_private_bytes(our_private_key)

        ratch = self.make_ratchet_as_reciever(shared_key=shared_key, our_private_key=our_private_key,
                                      their_public=their_pub_key, their_dh=their_dh_key)
        
        decode = ratch.decrypt_message(message["msg"])
        print(decode)
        

    def json_to_dr_format(self, message):
        message['msg']['nonce'] = bytes.fromhex(message['msg']['nonce'])
        message['msg']['ciphertext'] = bytes.fromhex(message['msg']['ciphertext'])
        return message
    
    def recursive_json(self, data):
        if isinstance(data, str):
            try:
                parsed = json.loads(data)
                return self.recursive_json(parsed)
            except:
                return data
        elif isinstance(data, dict):
            return {key: self.recursive_json(value) for key, value in data.items()}
        elif isinstance(data, list):
            return [self.recursive_json(item) for item in data]
        return data


    def make_ratchet_as_sender(self, shared_key: bytes, our_private_key: x25519.X25519PrivateKey, 
                               their_public: x25519.X25519PublicKey):
        our_exchange = our_private_key.exchange(their_public)
        our_send, our_recv = dr.initial_key_derivation(shared_key, our_exchange)

        our_ratchet = dr.DoubleRatchet(
            root_key = shared_key,
            dh_pair = our_private_key,
            remote_dh_public=their_public,
            sending_chain_key=our_send,
            receiving_chain_key=our_recv
        )
        return (our_ratchet, our_exchange)

    def make_ratchet_as_reciever(self, shared_key: bytes, our_private_key: x25519.X25519PrivateKey, 
                               their_public: x25519.X25519PublicKey, their_dh: bytes):
        our_recv, our_send = dr.initial_key_derivation(shared_key, their_dh)

        our_ratchet = dr.DoubleRatchet(
            root_key = shared_key,
            dh_pair = our_private_key,
            remote_dh_public=their_public,
            sending_chain_key=our_send,
            receiving_chain_key=our_recv
        )
        return our_ratchet

def main():
    
    bob = Client("bob", "1231231234")
    alice = Client("alice", "3213213210")

    bob.add_pub_key_serv(bob.make_keys())
    alice.send_first_message('1231231234', 'this is a message from alice')
    x = bob.get_oldest_msg_from_num('3213213210')
    bob.decode_first_message(x)

if __name__ == '__main__':
    main()