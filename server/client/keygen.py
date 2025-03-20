import sys
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import ed25519
import os
from pathlib import Path


try:
    RATCHAT_KEY_PATH = Path(os.environ.get("RATCHAT_KEY_PATH"))  # type: ignore
    ENCRYPTION_KEY_PATH = RATCHAT_KEY_PATH / "enc.key"
    PRIVATE_KEY_PATH = RATCHAT_KEY_PATH / "priv.key"
except Exception:
    print("Environment variables haven't been configured.", file=sys.stderr)
    raise


def encrypt(encrypt_key: bytes, private_key: bytes) -> bytes:
    return Fernet(encrypt_key).encrypt(private_key)


def decrypt(encrypt_key: bytes, private_key_encrypted: bytes) -> bytes:
    return Fernet(encrypt_key).decrypt(private_key_encrypted)


def generate_keys(encrypt_private_key: bool = False) -> tuple[bytes, bytes]:
    "Generates an Ed25519 private key as well as an encryption key for storing it."
    encrypt_key = Fernet.generate_key()
    private_key = ed25519.Ed25519PrivateKey.generate().private_bytes_raw()
    if encrypt_private_key:
        private_key = encrypt(encrypt_key, private_key)
    return encrypt_key, private_key


def store_keys(encrypt_key: bytes, private_key: bytes) -> None:
    """Writes `encrypt_key` and `private_key` to storage.
    Note that this overwrites any existing keys.
    """
    with open(ENCRYPTION_KEY_PATH, "wb+") as f1, open(PRIVATE_KEY_PATH, "wb+") as f2:
        f1.write(encrypt_key)
        f2.write(private_key)


def load_keys(decrypt_private_key: bool = False) -> tuple[bytes, bytes]:
    "Loads the encryption key and private key from storage."
    with open(ENCRYPTION_KEY_PATH, "rb") as f1, open(PRIVATE_KEY_PATH, "rb") as f2:
        encrypt_key = f1.read()
        private_key = f2.read()
        if decrypt_private_key:
            private_key = decrypt(encrypt_key, private_key)
    return encrypt_key, private_key


def get_pubkey(private_key: bytes, encrypt_key: bytes | None = None) -> bytes:
    "Returns the public key of an Ed25519 private key."
    if encrypt_key is not None:
        private_key = decrypt(encrypt_key, private_key)
    return (
        ed25519.Ed25519PrivateKey.from_private_bytes(private_key)
        .public_key()
        .public_bytes_raw()
    )


def reset_keys() -> None:
    os.remove(ENCRYPTION_KEY_PATH)
    os.remove(PRIVATE_KEY_PATH)


def main() -> None:
    encrypt_key, private_key = generate_keys()
    private_key_encrypted = encrypt(encrypt_key, private_key)
    print(
        f"{" Generating Keys ":=^100}",
        f"{encrypt_key = }",
        f"{private_key = }",
        f"{private_key_encrypted = }",
        sep="\n",
    )
    store_keys(encrypt_key, private_key_encrypted)
    print(
        "=" * 100,
        "Stored keys on computer.",
        "=" * 100,
        sep="\n",
    )


if __name__ == "__main__":
    main()
