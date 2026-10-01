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

#Rutas
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "secbank.db")
ROOT_DB = os.path.join(os.path.dirname(BASE_DIR), "secbank.db")
if not os.path.exists(DB_FILE) and os.path.exists(ROOT_DB):
    DB_FILE = ROOT_DB
MAX_LOGIN_ATTEMPTS = 3 #limite de intentos
REPLAY_WINDOW_SECONDS = 300  # Ventana de 5 minutos para timestamps.
#Si el timestamp anterior supera los 10 minutos (600), el ataque de prueba no funcionara. Revisar el archivo ataques.py
ACTIVE_SESSIONS: Dict[str, Dict[str, str]] = {} #sesiones activas

class UserCredentials(BaseModel):
    username: str
    password: str
def get_db_connection():
    return sqlite3.connect(DB_FILE)

# Aplica el algoritmo PBKDF2 con 100000 iteraciones y un salt
def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000).hex()

def compute_hmac_hex(key_hex: str, data_bytes: bytes) -> str:
    import hmac
    key_bytes = bytes.fromhex(key_hex)
    return hmac.new(key_bytes, data_bytes, hashlib.sha256).hexdigest()

#REGISTRO DE NUEVO USUARIO
@app.post("/api/v1/register", status_code=status.HTTP_201_CREATED)
def register_user(creds: UserCredentials):
    #restricciones en las contrasenas
    pwd = creds.password
    if len(pwd) < 8 or not any(c.isupper() for c in pwd) or not any(c.islower() for c in pwd) or not any(c.isdigit() for c in pwd) or not any(not c.isalnum() for c in pwd):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="La contraseña debe tener al menos 8 caracteres, incluir mayusculas, minusculas, numeros y un simbolo."
        )
    #se crea un salt al azar para el nuevo ususario
    salt=os.urandom(16)
    pwd_hash=hash_password(pwd, salt)
    conn=get_db_connection()
    cursor=conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, salt, failed_attempts) VALUES (?, ?, ?, 0)",
            (creds.username, pwd_hash, salt.hex()),
        )
        conn.commit()
    #Si el usuario ya existe no dejara crear uno con el mismo nombre
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
            detail="Credenciales incorrectas",
        )
    user_id, stored_hash, salt_hex, failed_attempts, locked_until = user

    #control de bloqueo por si hay muchos intentos fallidos
    #Tambien se verifica si ya esta bloqueada, de ser asi sera rechazado 
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

    #comparacion de tiempo
    #Con compare_digests se compara el tiempo para evitar ataques de timing
    if secrets.compare_digest(computed_hash, stored_hash):
        cursor.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,),
        )
        conn.commit()
        conn.close()

        # Generar clave
        session_id = secrets.token_hex(16)
        session_key = secrets.token_hex(32)

        ACTIVE_SESSIONS[session_id] = {
            "username": creds.username,
            "session_key": session_key,
        }

        return {
            "session_id": session_id,
            "session_key": session_key,
            "message": "Inicio de sesion exitoso",
        }
    else:
        #Si falla el inicio de sesion se va sumando 1 al contador, el total acumulado se puede ver mejor en DB Browser
        #El limite de intentos esta al inicio del codigo
        failed_attempts += 1
        if failed_attempts >= MAX_LOGIN_ATTEMPTS:
            #Si se llega al maximo numero de intentos se guarda la hora y se le suman 5 minutos
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
            detail="Credenciales incorrectas",
        )


@app.post("/api/v1/logout")
def logout_user(x_session_id: str = Header(None, alias="X-Session-ID")):
    if x_session_id and x_session_id in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[x_session_id]
        return {"message": "Sesion cerrada exitosamente."}
    return {"message": "La sesion no existia o ya estaba cerrada."}


@app.post("/api/v1/transfer")
async def transfer_money(
    request: Request,
    x_session_id: str = Header(None, alias="X-Session-ID"),
    x_signature: str = Header(None, alias="X-Signature"),
    x_nonce: str = Header(None, alias="X-Nonce"),
    x_timestamp: str = Header(None, alias="X-Timestamp"),
):
    #Verificar cabeceras 
    if not all([x_session_id, x_signature, x_nonce, x_timestamp]):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cabeceras incompletas",
        )

    session = ACTIVE_SESSIONS.get(x_session_id)
    if not session:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Sesion invalida o expirada.",
        )

    #verificar timestamp
    try:
        req_timestamp = int(x_timestamp)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalido",
        )
    #si la hora supera los 5 minutos se rechaza, el tiempo se encuentra al inicio del codigo en REPLAY_WINDOW_SECONDS
    current_time = int(time.time())
    if abs(current_time - req_timestamp) > REPLAY_WINDOW_SECONDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalido",
        )

    #verificar nonces
    #Si el nonce ya existe en la base de datos se identifica como ataque de replay
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT nonce FROM nonces WHERE nonce = ?", (x_nonce,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Ataque Replay detectado: El Nonce ya ha sido procesado previamente.",
        )

    #verificar hmacs
    #El servidor debe recalcular la firma de los datos que recibio con la clave
    raw_body = await request.body()
    expected_mac = compute_hmac_hex(session["session_key"], raw_body)

    #Si los datos fueron alterados, la firma no sera la misma y se deteccta como un Man in the middle
    if not secrets.compare_digest(expected_mac, x_signature):
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Fallo de integridad: HMAC no coincide (Ataque MitM o clave incorrecta).",
        )

    #Incertar en base de datos
    try:
        payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cuerpo JSON malformado.",
        )
    #Se agrega el nonce a la DB, una vez ingresado no peude volver a ser utilizado
    #Si se borra la base de datos tambien lo hacen los nonces por lo que pueden reutilizarse
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