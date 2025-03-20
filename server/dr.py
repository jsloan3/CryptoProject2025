from dataclasses import dataclass, field
import os
import hmac
import hashlib
from pprint import pformat

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def kdf_root(root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
    """
    Derives a new root key and chain key from the current root key and DH output.
    Uses HKDF to derive 64 bytes and splits them into two 32-byte keys.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=root_key,
        info=b"DoubleRatchetRoot",
        backend=default_backend(),
    )
    derived = hkdf.derive(dh_output)
    new_root = derived[:32]
    new_chain_key = derived[32:]
    return new_root, new_chain_key


def kdf_chain(chain_key: bytes) -> tuple[bytes, bytes]:
    """
    Implements the KDF chain step for the recieving and sending chains as defined in the Signal Double Ratchet specification.
    Given a chain key (CK), derive:
      - The message key (MK) = HMAC_SHA256(CK, 0x01)
      - The next chain key (CK') = HMAC_SHA256(CK, 0x02)

    Reference: https://signal.org/docs/specifications/doubleratchet/#kdf-chains :contentReference[oaicite:1]{index=1}
    """
    message_key = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
    new_chain_key = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
    return message_key, new_chain_key


@dataclass
class DoubleRatchet:
    root_key: bytes
    dh_pair: x25519.X25519PrivateKey
    remote_dh_public: x25519.X25519PublicKey
    sending_chain_key: bytes
    receiving_chain_key: bytes
    Nr: int = field(init=False, default=0)
    PN: int = field(init=False, default=0)
    Ns: int = field(init=False, default=0)
    dh_ratchet_sent: int = field(init=False, default=True)

    @property
    def remote_dh_public_bytes(self) -> bytes:
        return self.remote_dh_public.public_bytes_raw()

    def dh_ratchet_update(self, new_remote_dh_public: x25519.X25519PublicKey):
        """
        Performs a DH ratchet update upon receiving a message with a new DH public key.
        This updates the root key, receiving chain, and then creates a new DH key pair
        to update the sending chain.
        """
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0

        # Update root and receiving chain with our current DH key and the new remote key.
        dh_output = self.dh_pair.exchange(new_remote_dh_public)
        self.root_key, self.receiving_chain_key = kdf_root(self.root_key, dh_output)
        self.remote_dh_public = new_remote_dh_public  # Set the new remote DH key.

        # Generate a new DH key pair for our side.
        self.dh_pair = x25519.X25519PrivateKey.generate()

        # Update root and sending chain with our new DH key and the new remote key.
        dh_output = self.dh_pair.exchange(self.remote_dh_public)
        self.root_key, self.sending_chain_key = kdf_root(self.root_key, dh_output)

        # Mark that we need to include our new DH public key in the next message.
        self.dh_ratchet_sent = False

    def encrypt_message(self, plaintext: str) -> dict:
        """
        Encrypts a plaintext message.
        When a DH ratchet update has just occurred, includes our new DH public key in the header.
        """
        self.dh_ratchet_sent = False  # Change made

        if not self.dh_ratchet_sent:
            dh_bytes = self.dh_pair.public_key().public_bytes_raw()
            header = {"dh": dh_bytes, "pn": self.PN, "n": self.Ns}
            self.dh_ratchet_sent = True
        else:
            header = {"dh": None, "pn": None, "n": self.Ns}

        # Derive the message key and update the sending chain key.
        message_key, self.sending_chain_key = kdf_chain(self.sending_chain_key)
        self.Ns += 1

        aesgcm = AESGCM(message_key)
        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)

        return {"header": header, "nonce": nonce, "ciphertext": ciphertext}

    def decrypt_message(self, message: dict) -> str:
        """
        Decrypts a received message.
        If the message header contains a new DH public key, perform a DH ratchet update first.
        """
        header = message["header"]
        if header["dh"] is not None:
            received_dh = header["dh"]
            if received_dh != self.remote_dh_public_bytes:
                new_remote_dh_public = x25519.X25519PublicKey.from_public_bytes(
                    received_dh
                )
                self.dh_ratchet_update(new_remote_dh_public)

        # If messages are skipped, the receiving chain would be advanced (this example assumes in‑order delivery).
        while self.Nr < header["n"]:
            _, self.receiving_chain_key = kdf_chain(self.receiving_chain_key)
            self.Nr += 1

        message_key, self.receiving_chain_key = kdf_chain(self.receiving_chain_key)
        self.Nr += 1

        aesgcm = AESGCM(message_key)
        plaintext = aesgcm.decrypt(message["nonce"], message["ciphertext"], None)
        return plaintext.decode()


def initial_key_derivation(
    shared_secret: bytes, dh_output: bytes
) -> tuple[bytes, bytes]:
    """
    Derives two 32-byte keys from a shared secret and a DH output.
    One key will serve as the sending chain key and the other as the receiving chain key.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=shared_secret,
        info=b"DoubleRatchetInitial",
        backend=default_backend(),
    )
    derived = hkdf.derive(dh_output)
    return derived[:32], derived[32:]


def main() -> None:
    # === Initial Setup ===
    # Both parties (Alice and Bob) start with a shared secret (from a pre-key or other key agreement)
    shared_secret = os.urandom(32)

    # Each party generates an initial ephemeral DH key pair.
    alice_dh = x25519.X25519PrivateKey.generate()
    bob_dh = x25519.X25519PrivateKey.generate()

    alice_pub = alice_dh.public_key()
    bob_pub = bob_dh.public_key()

    # Perform a DH exchange.
    dh_output = alice_dh.exchange(bob_pub)

    # Derive initial chain keys. For simplicity, one party’s sending key is the other’s receiving key.
    alice_send, alice_recv = initial_key_derivation(shared_secret, dh_output)
    bob_recv, bob_send = initial_key_derivation(shared_secret, dh_output)

    # Initialize the Double Ratchet instances for both parties.
    alice_ratchet = DoubleRatchet(
        root_key=shared_secret,
        dh_pair=alice_dh,
        remote_dh_public=bob_pub,
        sending_chain_key=alice_send,
        receiving_chain_key=alice_recv,
    )

    bob_ratchet = DoubleRatchet(
        root_key=shared_secret,
        dh_pair=bob_dh,
        remote_dh_public=alice_pub,
        sending_chain_key=bob_send,
        receiving_chain_key=bob_recv,
    )

    # === Simulated Conversation ===

    # Alice sends a message.
    msg1 = alice_ratchet.encrypt_message("Hello Bob!")
    print("Alice sends:", pformat(msg1))

    # Bob decrypts the message.
    plaintext1 = bob_ratchet.decrypt_message(msg1)
    print("Bob receives:", pformat(plaintext1))

    # Bob replies.
    msg2 = bob_ratchet.encrypt_message("Hello Alice!")
    print("Bob sends:", pformat(msg2))

    # Alice decrypts Bob's reply.
    plaintext2 = alice_ratchet.decrypt_message(msg2)
    print("Alice receives:", pformat(plaintext2))

    # --- Trigger a DH Ratchet Update ---
    # Alice sends a message that includes her new DH public key in the header.
    msg3 = alice_ratchet.encrypt_message("How are you?")
    print("Alice sends:", pformat(msg3))

    # When Bob decrypts msg3, he detects the new DH public key and performs a DH ratchet update.
    plaintext3 = bob_ratchet.decrypt_message(msg3)
    print("Bob receives:", pformat(plaintext3))


if __name__ == "__main__":
    main()
