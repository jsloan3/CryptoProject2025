import requests
import os
import json
import keygen

HOSTNAME = "http://127.0.0.1:5000"
os.putenv("RATCHAT_KEY_PATH", os.path.abspath("./keys"))

def main():
    if not check_for_data():
        register()
    
    with open("userdata.json", "r") as file:
        userdata = json.load(file)

    #print(name_from_phone("123456789"))


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



def check_for_data():
    file = 'userdata.json'
    return os.path.isfile(file) and os.path.getsize(file) != 0



if __name__ == "__main__":
    main()
