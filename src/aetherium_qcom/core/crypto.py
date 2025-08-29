# aetherium_qcom/core/crypto.py
import base64
import json
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.sign import ml_dsa_87
from pqcrypto.kem import ml_kem_1024

class CryptoManager:
    @staticmethod
    def generate_ephemeral_keys():
        pk, sk = ml_dsa_87.generate_keypair()
        return base64.b64encode(pk).decode(), base64.b64encode(sk).decode()

    @staticmethod
    def generate_persistent_keys():
        pk_d, sk_d = ml_dsa_87.generate_keypair()
        pk_k, sk_k = ml_kem_1024.generate_keypair()
        return {"sign_pk": base64.b64encode(pk_d).decode(), "sign_sk": base64.b64encode(sk_d).decode(),
                "kem_pk": base64.b64encode(pk_k).decode(), "kem_sk": base64.b64encode(sk_k).decode()}

    @staticmethod
    def sign_hash(signing_key_b64, hash_hex):
        try:
            sk_bytes = base64.b64decode(signing_key_b64)
            return base64.b64encode(ml_dsa_87.sign(sk_bytes, hash_hex.encode())).decode()
        except Exception: return None

    @staticmethod
    def verify_hash_signature(public_key_b64, signature_b64, hash_hex):
        try:
            pk_bytes = base64.b64decode(public_key_b64)
            sig_bytes = base64.b64decode(signature_b64)
            return ml_dsa_87.verify(pk_bytes, hash_hex.encode(), sig_bytes)
        except Exception: return False
    
    @staticmethod
    def sign_data(signing_key, data):
        try:
            return base64.b64encode(ml_dsa_87.sign(base64.b64decode(signing_key), json.dumps(data, sort_keys=True).encode())).decode()
        except Exception: return None

    @staticmethod
    def verify_signature(signing_pk, signature, data):
        try:
            data_bytes = json.dumps(data, sort_keys=True).encode()
            return ml_dsa_87.verify(base64.b64decode(signing_pk), data_bytes, base64.b64decode(signature))
        except Exception: return False

    @staticmethod
    def create_invitation(issuer_id, issuer_keys, bootstrap_nodes):
        data = {"issuer_id": issuer_id, "issuer_kem_pk": issuer_keys["kem_pk"], 
                "issuer_sign_pk": issuer_keys["sign_pk"], "bootstrap_nodes": bootstrap_nodes}
        sig = ml_dsa_87.sign(base64.b64decode(issuer_keys["sign_sk"]), json.dumps(data, sort_keys=True).encode())
        return {"payload": data, "signature": base64.b64encode(sig).decode()}

    @staticmethod
    def verify_invitation(invitation):
        try:
            payload_bytes = json.dumps(invitation['payload'], sort_keys=True).encode()
            return ml_dsa_87.verify(base64.b64decode(invitation['payload']['issuer_sign_pk']), payload_bytes, base64.b64decode(invitation['signature']))
        except Exception: return False
    
    @staticmethod
    def aead_encrypt(key_b64, data_bytes):
        key = hashlib.sha256(base64.b64decode(key_b64)).digest()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data_bytes, None)
        return nonce + ciphertext

    @staticmethod
    def aead_decrypt(key_b64, encrypted_data_with_nonce):
        key = hashlib.sha256(base64.b64decode(key_b64)).digest()
        nonce = encrypted_data_with_nonce[:12]
        ciphertext = encrypted_data_with_nonce[12:]
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            return None