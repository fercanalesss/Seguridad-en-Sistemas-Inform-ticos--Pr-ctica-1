"""
crypto_utils.py
Funciones criptográficas auxiliares para SecBank.
Cumple con los requisitos RS2 (HMAC-SHA256) y RS3 (Nonce y Timestamp).
"""

import hashlib
import hmac
import time
import uuid


def generate_nonce() -> str:
    """
    Genera un NONCE criptográficamente seguro basado en UUIDv4.
    Requisito: RS3.a
    """
    return str(uuid.uuid4())


def get_current_timestamp() -> int:
    """
    Devuelve la marca de tiempo Unix actual en segundos como un entero.
    Requisito: RS3.a
    """
    return int(time.time())


def calculate_hmac(key_hex: str, message_bytes: bytes) -> str:
    """
    Calcula el código HMAC-SHA256 sobre los bytes del mensaje usando la clave de sesión.

    :param key_hex: Clave secreta de 256 bits en formato hexadecimal.
    :param message_bytes: Carga útil en bytes brutos (UTF-8).
    :return: Digest hexadecimal en minúsculas.
    Requisitos: RS2.a, RS2.b
    """
    key_bytes = bytes.fromhex(key_hex)
    mac = hmac.new(key_bytes, message_bytes, hashlib.sha256)
    return mac.hexdigest()