# crypto_utils.py

import os
import base64

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Size constants used in the cryptographic protocol.
SALT_SIZE = 16
SESSION_ID_SIZE = 16
AES_KEY_SIZE = 32          # 32 bytes = 256 bits
AES_GCM_NONCE_SIZE = 12    # Recommended nonce size for AES-GCM
PBKDF2_ITERATIONS = 600_000

def generate_salt() -> bytes:
    """
    Generate a random salt for password-based key derivation.

    The salt is not secret. It is sent to the peer so both users can derive
    the same master key from the shared password.
    """
    return os.urandom(SALT_SIZE)


def generate_session_id() -> bytes:
    """
    Generate a random session identifier.

    The session ID separates key material between different chat sessions.
    It is used as input when deriving session keys.
    """
    return os.urandom(SESSION_ID_SIZE)


def derive_master_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit master key from a shared password.

    PBKDF2-HMAC-SHA256 is used so the password is not directly used as an
    encryption key. The salt must match on both peers for them to derive
    the same master key.
    """
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
    """
    Derive the current AES session key from the master key.

    HKDF-SHA256 derives a 256-bit session key using the session ID and
    rekey counter. Incrementing the rekey counter produces a new session key.
    """
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
    """
    Encrypt a plaintext message using AES-GCM.

    A new random nonce is generated for every message. The returned
    ciphertext includes the AES-GCM authentication tag and is base64-encoded
    for JSON transmission.
    """
    nonce = os.urandom(AES_GCM_NONCE_SIZE)
    aesgcm = AESGCM(session_key)

    plaintext_bytes = plaintext.encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad)

    return {
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_message(session_key: bytes, packet: dict, aad: bytes = b"") -> str:
    """
    Decrypt and authenticate an AES-GCM encrypted message packet.

    The packet must contain base64-encoded 'nonce' and 'ciphertext' fields.
    If authentication fails, the message is rejected with a ValueError.
    """
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