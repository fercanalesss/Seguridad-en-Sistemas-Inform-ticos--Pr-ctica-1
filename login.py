import hashlib
import sqlite3
from datetime import datetime, timedelta

MAX_INTENTOS = 3  # Número máximo de intentos antes de bloquear


def iniciar_sesion(username, password):
  conn = sqlite3.connect("secbank.db")
  cursor = conn.cursor()

  # 1. Buscar al usuario en la base de datos
  cursor.execute(
      """
        SELECT id, password_hash, salt, failed_attempts, locked_until 
        FROM users WHERE username = ?
    """,
      (username,),
  )
  user = cursor.fetchone()

  if not user:
    print("Error: Credenciales inválidas.")
    conn.close()
    return False

  user_id, stored_hash, salt_hex, failed_attempts, locked_until = user

  # 2. Verificar si el usuario está bloqueado por fuerza bruta (RS1)
  if locked_until:
    lock_time = datetime.fromisoformat(locked_until)
    if datetime.now() < lock_time:
      print(
          f"Demasiados intentos fallidos. Cuenta bloqueada temporalmente hasta"
          f" {lock_time.strftime('%H:%M:%S')}."
      )
      conn.close()
      return False
    else:
      cursor.execute(
          "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id ="
          " ?",
          (user_id,),
      )
      conn.commit()

  # 3. Recalcular el hash de la contraseña ingresada usando el salt almacenado
  salt = bytes.fromhex(salt_hex)
  pwd_bytes = password.encode("utf-8")
  key = hashlib.pbkdf2_hmac("sha256", pwd_bytes, salt, 100000)
  input_hash = key.hex()

  # 4. Validar si la contraseña coincide
  if input_hash == stored_hash:
    cursor.execute(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
        (user_id,),
    )
    conn.commit()
    conn.close()
    print(f"¡Bienvenido a SecBank, {username}! Inicio de sesión exitoso.")
    return True
  else:
    failed_attempts += 1
    if failed_attempts >= MAX_INTENTOS:
      lock_time = datetime.now() + timedelta(minutes=5)
      cursor.execute(
          """
                UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?
            """,
          (failed_attempts, lock_time.isoformat(), user_id),
      )
      print(
          f"Contraseña incorrecta. Has superado los {MAX_INTENTOS} intentos."
          " Cuenta bloqueada por 5 minutos."
      )
    else:
      cursor.execute(
          "UPDATE users SET failed_attempts = ? WHERE id = ?",
          (failed_attempts, user_id),
      )
      print(
          f"Contraseña incorrecta. Intentos restantes:"
          f" {MAX_INTENTOS - failed_attempts}"
      )

    conn.commit()
    conn.close()
    return False


if __name__ == "__main__":
  print("=== LOGIN SECBANK ===")
  user_ingresado = input("Ingresa tu usuario: ")
  pass_ingresada = input("Ingresa tu contraseña: ")

  iniciar_sesion(user_ingresado, pass_ingresada)
