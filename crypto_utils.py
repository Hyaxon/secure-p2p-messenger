# crypto_utils.py

import os
import base64

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


SALT_SIZE = 16
SESSION_ID_SIZE = 16
AES_KEY_SIZE = 32          # 32 bytes = 256 bits
AES_GCM_NONCE_SIZE = 12    # Recommended nonce size for GCM
PBKDF2_ITERATIONS = 600_000


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def generate_session_id() -> bytes:
    return os.urandom(SESSION_ID_SIZE)


def derive_master_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")

    password_bytes = password.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )

    return kdf.derive(password_bytes)


def derive_session_key(master_key: bytes, session_id: bytes, rekey_counter: int) -> bytes:
    if rekey_counter < 0:
        raise ValueError("Rekey counter cannot be negative.")

    info = (
        b"secure-p2p-session-key:"
        + session_id
        + rekey_counter.to_bytes(4, "big")
    )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,
        info=info,
    )

    return hkdf.derive(master_key)


def encrypt_message(session_key: bytes, plaintext: str, aad: bytes = b"") -> dict:
    nonce = os.urandom(AES_GCM_NONCE_SIZE)
    aesgcm = AESGCM(session_key)

    plaintext_bytes = plaintext.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad)

    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_message(session_key: bytes, packet: dict, aad: bytes = b"") -> str:
    try:
        nonce = base64.b64decode(packet["nonce"])
        ciphertext = base64.b64decode(packet["ciphertext"])

        aesgcm = AESGCM(session_key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)

        return plaintext_bytes.decode("utf-8")

    except InvalidTag:
        raise ValueError("Message authentication failed. Ciphertext may have been modified.")
    except KeyError:
        raise ValueError("Invalid encrypted packet format.")