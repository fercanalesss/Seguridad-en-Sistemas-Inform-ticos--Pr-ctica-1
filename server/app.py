"""
server/app.py
Servidor REST para SecBank
Ejecutado sobre HTTP no seguro (puerto 8080, sin TLS/HTTPS).
Implementa las validaciones de seguridad RS1, RS2, RS3 y RS4.
"""

from datetime import datetime, timedelta
import hashlib
import json
import os
import secrets
import sqlite3
import time
from typing import Dict

from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel

app = FastAPI(title="SecBank API", version="1.0.0")

# Rutas de base de datos (comprueba si está en server/ o en la raíz)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "secbank.db")
ROOT_DB = os.path.join(os.path.dirname(BASE_DIR), "secbank.db")
if not os.path.exists(DB_FILE) and os.path.exists(ROOT_DB):
    DB_FILE = ROOT_DB

MAX_LOGIN_ATTEMPTS = 3
REPLAY_WINDOW_SECONDS = 300  # Ventana de 5 minutos para timestamps

# Almacén de sesiones activas en memoria: {session_id: {"username": str, "session_key": str}}
ACTIVE_SESSIONS: Dict[str, Dict[str, str]] = {}


# --- MODELOS DE DATOS ---

class UserCredentials(BaseModel):
    username: str
    password: str


# --- FUNCIONES AUXILIARES DE BASE DE DATOS Y SEGURIDAD ---

def get_db_connection():
    return sqlite3.connect(DB_FILE)


def hash_password(password: str, salt: bytes) -> str:
    """RS1.a: Derivación de clave adaptativa mediante PBKDF2-HMAC-SHA256 (100.000 iteraciones)."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000).hex()


def compute_hmac_hex(key_hex: str, data_bytes: bytes) -> str:
    """RS2: Cálculo de HMAC-SHA256."""
    import hmac
    key_bytes = bytes.fromhex(key_hex)
    return hmac.new(key_bytes, data_bytes, hashlib.sha256).hexdigest()


# --- ENDPOINTS REST ---

@app.post("/api/v1/register", status_code=status.HTTP_201_CREATED)
def register_user(creds: UserCredentials):
    """Registro de nuevos usuarios con salt aleatorio y PBKDF2."""
    salt = os.urandom(16)
    pwd_hash = hash_password(creds.password, salt)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, failed_attempts) VALUES (?, ?, ?, 0)",
            (creds.username, pwd_hash, salt.hex()),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"El usuario '{creds.username}' ya existe.",
        )
    finally:
        conn.close()

    return {"message": f"Usuario '{creds.username}' registrado exitosamente."}


@app.post("/api/v1/login")
def login_user(creds: UserCredentials):
    """
    Autenticación de usuario con protección frente a fuerza bruta (RS1.b).
    Genera y devuelve una session_id y una session_key de 256 bits (RS2.b).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, password_hash, salt, failed_attempts, locked_until FROM users WHERE username = ?",
        (creds.username,),
    )
    user = cursor.fetchone()

    if not user:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
        )

    user_id, stored_hash, salt_hex, failed_attempts, locked_until = user

    # Control de bloqueo por fuerza bruta (RS1.b)
    if locked_until:
        lock_time = datetime.fromisoformat(locked_until)
        if datetime.now() < lock_time:
            conn.close()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Cuenta bloqueada temporalmente hasta {lock_time.strftime('%H:%M:%S')}.",
            )
        else:
            cursor.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
                (user_id,),
            )
            conn.commit()

    salt = bytes.fromhex(salt_hex)
    computed_hash = hash_password(creds.password, salt)

    # RS4: Comparación en tiempo constante
    if secrets.compare_digest(computed_hash, stored_hash):
        cursor.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,),
        )
        conn.commit()
        conn.close()

        # Generación de clave de sesión criptográfica de 256 bits (32 bytes = 64 hex chars)
        session_id = secrets.token_hex(16)
        session_key = secrets.token_hex(32)

        ACTIVE_SESSIONS[session_id] = {
            "username": creds.username,
            "session_key": session_key,
        }

        return {
            "session_id": session_id,
            "session_key": session_key,
            "message": "Inicio de sesión exitoso.",
        }
    else:
        failed_attempts += 1
        if failed_attempts >= MAX_LOGIN_ATTEMPTS:
            lock_time = datetime.now() + timedelta(minutes=5)
            cursor.execute(
                "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                (failed_attempts, lock_time.isoformat(), user_id),
            )
        else:
            cursor.execute(
                "UPDATE users SET failed_attempts = ? WHERE id = ?",
                (failed_attempts, user_id),
            )
        conn.commit()
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas.",
        )


@app.post("/api/v1/logout")
def logout_user(x_session_id: str = Header(None, alias="X-Session-ID")):
    """Cierra la sesión activa revocando las claves asociadas."""
    if x_session_id and x_session_id in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[x_session_id]
        return {"message": "Sesión cerrada exitosamente."}
    return {"message": "La sesión no existía o ya estaba cerrada."}


@app.post("/api/v1/transfer")
async def transfer_money(
    request: Request,
    x_session_id: str = Header(None, alias="X-Session-ID"),
    x_signature: str = Header(None, alias="X-Signature"),
    x_nonce: str = Header(None, alias="X-Nonce"),
    x_timestamp: str = Header(None, alias="X-Timestamp"),
):
    """
    Procesa órdenes de transferencia bancaria verificando integridad,
    autenticidad y protegiendo contra ataques de repetición (Replay).
    """
    # 1. Verificación de presencia de cabeceras obligatorias
    if not all([x_session_id, x_signature, x_nonce, x_timestamp]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cabeceras de seguridad incompletas (X-Session-ID, X-Signature, X-Nonce, X-Timestamp).",
        )

    session = ACTIVE_SESSIONS.get(x_session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesión inválida o expirada.",
        )

    # 2. RS3: Verificación de ventana temporal del timestamp
    try:
        req_timestamp = int(x_timestamp)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Formato de timestamp inválido.",
        )

    current_time = int(time.time())
    if abs(current_time - req_timestamp) > REPLAY_WINDOW_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Petición rechazada: Timestamp fuera de la ventana válida.",
        )

    # 3. RS3: Verificación y registro de Nonce contra ataques de repetición
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT nonce FROM nonces WHERE nonce = ?", (x_nonce,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ataque Replay detectado: El Nonce ya ha sido procesado previamente.",
        )

    # 4. RS2 y RS4: Verificación HMAC en tiempo constante
    raw_body = await request.body()
    expected_mac = compute_hmac_hex(session["session_key"], raw_body)

    if not secrets.compare_digest(expected_mac, x_signature):
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Fallo de integridad: HMAC no coincide (Ataque MitM o clave incorrecta).",
        )

    # 5. Deserialización e inserción en base de datos
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cuerpo JSON malformado.",
        )

    cursor.execute("INSERT INTO nonces (nonce, timestamp) VALUES (?, ?)", (x_nonce, req_timestamp))

    cursor.execute(
        """
        INSERT INTO transactions (tx_id, origin_account, destination_account, amount, currency, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            payload["tx_id"],
            payload["origin_account"],
            payload["destination_account"],
            payload["amount"],
            payload["currency"],
            req_timestamp,
        ),
    )
    conn.commit()
    conn.close()

    return {"status": "SUCCESS", "tx_id": payload["tx_id"]}