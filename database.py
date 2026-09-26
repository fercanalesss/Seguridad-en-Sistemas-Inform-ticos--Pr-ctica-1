import sqlite3
import hashlib
import os

def init_db():
    conn = sqlite3.connect("secbank.db")
    cursor = conn.cursor()

    # 1. Tabla de Usuarios
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            locked_until TIMESTAMP DEFAULT NULL
        )
    """)

    # 2. Tabla de Nonces (Para evitar ataques de Replay - Requisito RS3)[cite: 1]
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            nonce TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL
        )
    """)

    # 3. Tabla de Transacciones
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            tx_id TEXT PRIMARY KEY,
            origin_account TEXT NOT NULL,
            destination_account TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )
    """)

    # --- USUARIOS PRE-REGISTRADOS CON CONTRASEÑAS FUERTES ---
    usuarios_prueba = [
        ("fernanda_canales", "F3rn4nd4_C@n@l3s#2026!SecBank"),
        ("sonja_hohmann", "S0nj@_H0hm@nn$9876*Secure"),
        ("erick_villalobos", "3r1ck_V1ll@l0b0s%2026_Tx")
    ]

    for username, password in usuarios_prueba:
        # Generamos un salt único por usuario (Requisito RS1)[cite: 1]
        salt = os.urandom(16)
        pwd_bytes = password.encode('utf-8')
        # Derivación de clave adaptativa (PBKDF2-HMAC-SHA256)[cite: 1]
        key = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, 100000)
        
        password_hash = key.hex()
        salt_hex = salt.hex()

        try:
            cursor.execute("""
                INSERT INTO users (username, password_hash, salt) 
                VALUES (?, ?, ?)
            """, (username, password_hash, salt_hex))
            print(f"[+] Usuario pre-registrado creado: {username}")
        except sqlite3.IntegrityError:
            # Si ya existían de una ejecución anterior, no pasa nada
            pass

    conn.commit()
    conn.close()
    print("Base de datos inicializada correctamente con tablas y usuarios de prueba.")

if __name__ == "__main__":
    init_db()
