from dataclasses import dataclass, field
import json, os, hmac, hashlib, base64
from pprint import pformat

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM



def adversary_decrypt(message: str, key: str, nonce: str):
    key = bytes.fromhex(key)
    aesgcm = AESGCM(key)
    message = bytes.fromhex(message)
    nonce = bytes.fromhex(nonce)
    plaintext = aesgcm.decrypt(nonce, message, None)
    print(plaintext.decode())



if __name__ == "__main__":
    key = '145488523ddc881080408a5a1ccc1f28547168b1f5a940fa9ddaa0ede3749125'
    ciphertext = '383f5777ae80ecb42245669e7b98d21824d5e95c2859e2ca20c6cd257767461c62fa'
    nonce = '1c3be574c0a8a4890318100f'

    adversary_decrypt(ciphertext, key, nonce)

    ciphertext = '751b696050ab9be64c29ab0623750fbe597ad8fa204562baca81c382'
    nonce = '91ec21d0ba1acec464e39939'

    #adversary_decrypt(ciphertext, key, nonce)

    ciphertext = 'f17d8f61c2682e68ace955f9c09c39ebf165a9bad10d9c4b1bf8fff34a9d7775ad1562'
    nonce = 'bf0ac1e7d0533322c13e799f'

    adversary_decrypt(ciphertext, key, nonce)