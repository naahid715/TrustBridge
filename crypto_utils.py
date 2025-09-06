
from __future__ import annotations
import os
import base64
from typing import Tuple, Dict
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet

KEY_DIR = os.path.join(os.path.dirname(__file__), "keys")
GOVT_PRIV_PATH = os.path.join(KEY_DIR, "govt_private.pem")
GOVT_PUB_PATH  = os.path.join(KEY_DIR, "govt_public.pem")
JUDGE_PRIV_PATH = os.path.join(KEY_DIR, "judge_private.pem")
JUDGE_PUB_PATH  = os.path.join(KEY_DIR, "judge_public.pem")


def _write_pem_private(path, private_key):
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def _write_pem_public(path, public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem)


def ensure_keys() -> None:
    """Generate RSA keypairs for Govt and Judge if missing (demo-use only)."""
    os.makedirs(KEY_DIR, exist_ok=True)

    if not (os.path.exists(GOVT_PRIV_PATH) and os.path.exists(GOVT_PUB_PATH)):
        govt_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _write_pem_private(GOVT_PRIV_PATH, govt_priv)
        _write_pem_public(GOVT_PUB_PATH, govt_priv.public_key())

    if not (os.path.exists(JUDGE_PRIV_PATH) and os.path.exists(JUDGE_PUB_PATH)):
        judge_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _write_pem_private(JUDGE_PRIV_PATH, judge_priv)
        _write_pem_public(JUDGE_PUB_PATH, judge_priv.public_key())


def load_private_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path: str):
    with open(path, "rb") as f:
        return serialization.load_pem_public_key(f.read())


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def encrypt_record(plaintext: bytes) -> Dict[str, str]:
    """Encrypt data with Fernet key split into two RSA-encrypted XOR shares."""
    fernet_key_b64 = Fernet.generate_key()
    fernet_key_raw = base64.urlsafe_b64decode(fernet_key_b64)

    mask = os.urandom(len(fernet_key_raw))
    share_judge_raw = mask
    share_govt_raw = xor_bytes(fernet_key_raw, mask)

    govt_pub = load_public_key(GOVT_PUB_PATH)
    judge_pub = load_public_key(JUDGE_PUB_PATH)

    enc_share_govt = govt_pub.encrypt(
        share_govt_raw,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    enc_share_judge = judge_pub.encrypt(
        share_judge_raw,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

    token = Fernet(fernet_key_b64).encrypt(plaintext)

    return {
        "ciphertext_b64": base64.urlsafe_b64encode(token).decode(),
        "enc_share_govt_b64": base64.urlsafe_b64encode(enc_share_govt).decode(),
        "enc_share_judge_b64": base64.urlsafe_b64encode(enc_share_judge).decode(),
    }


def judge_decrypt_share(enc_share_judge_b64: str) -> bytes:
    """Judge uses private key to decrypt their share (raw bytes)."""
    enc = base64.urlsafe_b64decode(enc_share_judge_b64.encode())
    judge_priv = load_private_key(JUDGE_PRIV_PATH)
    share_raw = judge_priv.decrypt(
        enc,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    return share_raw


def govt_decrypt_and_reveal(payload: Dict[str, str], judge_share_raw: bytes) -> bytes:
    """Govt uses their private key to get their share, combines with judge_share_raw,
    reconstructs the Fernet key, and returns decrypted plaintext bytes."""
    enc_share_govt = base64.urlsafe_b64decode(payload["enc_share_govt_b64"].encode())
    govt_priv = load_private_key(GOVT_PRIV_PATH)
    share_govt_raw = govt_priv.decrypt(
        enc_share_govt,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )

    fernet_key_raw = xor_bytes(judge_share_raw, share_govt_raw)
    fernet_key_b64 = base64.urlsafe_b64encode(fernet_key_raw)

    token = base64.urlsafe_b64decode(payload["ciphertext_b64"].encode())
    plaintext = Fernet(fernet_key_b64).decrypt(token)
    return plaintext
