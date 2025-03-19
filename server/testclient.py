import requests
from keygen import load_keys, get_pubkey
import base64

HOSTNAME = "http://127.0.0.1:5000/register"


def main() -> None:
    encrypt_key, private_key_encrypted = load_keys()
    public_key = get_pubkey(private_key_encrypted, encrypt_key)
    to_send = {
        "PhoneNum": "444-444-4444",
        "Name": "John Smith",
        "EdPublic": public_key.hex(),
    }
    server_response = requests.post(HOSTNAME, json=to_send)
    print(server_response)


if __name__ == "__main__":
    main()
