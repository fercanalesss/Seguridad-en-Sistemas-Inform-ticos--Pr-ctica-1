import sqlite3
import hashlib
import os

def registrar_usuario(username, password):
    conn = sqlite3.connect("secbank.db")
    cursor = conn.cursor()

    # 1. Verificar si el usuario ya existe
    cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
    if cursor.fetchone():
        print(f"Error: El usuario '{username}' ya existe.")
        conn.close()
        return False

    # 2. Generar un salt aleatorio único por usuario 
    salt = os.urandom(16) # 16 bytes de sal aleatoria
    salt_hex = salt.hex()

    # 3. Derivar la contraseña usando PBKDF2-HMAC-SHA256 con 100,000 iteraciones
    pwd_bytes = password.encode('utf-8')
    key = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, 100000)
    password_hash = key.hex()

    # 4. Guardar en la base de datos
    cursor.execute("""
        INSERT INTO users (username, password_hash, salt, failed_attempts)
        VALUES (?, ?, ?, 0)
    """, (username, password_hash, salt_hex))

    conn.commit()
    conn.close()
    print(f"¡Usuario '{username}' registrado exitosamente de forma segura!")
    return True

if __name__ == "__main__":
    pass
