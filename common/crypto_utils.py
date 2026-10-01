import hashlib
import hmac
import time
import uuid

#Generar nonces
def generate_nonce() -> str:
    return str(uuid.uuid4())


def get_current_timestamp() -> int:
    return int(time.time())

#Calcular Hmac
def calculate_hmac(key_hex: str, message_bytes: bytes) -> str:
    key_bytes = bytes.fromhex(key_hex)
    mac = hmac.new(key_bytes, message_bytes, hashlib.sha256)
    return mac.hexdigest()