import sqlite3
import hashlib
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secbank.db")

def init_db():
    conn= sqlite3.connect("secbank.db")
    cursor=conn.cursor()
    # Tabla Usuarios
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

    #Nonces
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS nonces (
            nonce TEXT PRIMARY KEY,
            timestamp INTEGER NOT NULL
        )
    """)

    #Transacciones
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

    #usuarios para probar, para agregar primero escribir wl usuario luego el password
    #Agregar un usuario desde aqui ignora las restricciones al crear passwords
    usuarios_prueba=[
        ("fernanda_canales", "FerCan1!#"),
        ("sonja_hohmann", "S0njaH?2#"),
        ("erick_villalobos", "ErickVi14!#")
    ]

    for username, password in usuarios_prueba:
        salt =os.urandom(16) #Para cada ususario se genera un salt
        pwd_bytes=password.encode('utf-8')
        key=hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt, 100000) #se aplica la funcion pbkdf2 pra convertir de texto plano a una cadena hexadecimal
        password_hash=key.hex()
        salt_hex=salt.hex()
        try:
            cursor.execute("""
                INSERT INTO users (username, password_hash, salt)
                VALUES (?, ?, ?)
            """, (username,password_hash,salt_hex))
            print(f"[+] Usuario pre-registrado creado:{username}")
        except sqlite3.IntegrityError:
            pass
    
    conn.commit() #Guardar la base de datos en el archivo secbank.py
    conn.close() #cerrar conexion
    print("Base de datos inicializada correctamente con tablas y usuarios de prueba.")

if __name__ == "__main__":
    init_db()
