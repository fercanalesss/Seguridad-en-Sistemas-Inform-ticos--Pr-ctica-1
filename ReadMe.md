
### Mensaje / Informe para el equipo

**Asunto: Arquitectura Cliente-Servidor REST, Integración de Módulos y Trazabilidad de Requisitos (Rol 2)**

Hola a todos,

He estado trabajando en la capa de comunicación y el cliente (Rol 2). Siguiendo las directrices de la práctica (Opción B: API REST sobre HTTP plano en el puerto 8080, sin TLS), hemos reorganizado el proyecto en una arquitectura cliente-servidor real para que el cliente y el servidor se ejecuten de forma independiente a través de la red local.

A continuación os explico cómo está estructurado el sistema, cómo se integró el trabajo previo y cómo se cumplen los requisitos de seguridad (RS).

---

### 1. Estructura modular del proyecto

Para mantener el código limpio y separar responsabilidades, la estructura de carpetas ha quedado así:

```text
├── common/
│   └── crypto_utils.py        # Generación de Nonce (UUIDv4), Timestamp y HMAC-SHA256
├── server/
│   ├── app.py                 # Servidor FastAPI (Endpoints REST, control de sesiones y validaciones)
│   ├── database.py            # Esquema SQLite y precarga de usuarios (código de Fernanda)
│   └── secbank.db             # Base de datos SQLite
├── client/
│   ├── secbank_client.py      # Clase cliente (peticiones HTTP, serialización y firma HMAC)
│   └── cli.py                 # Interfaz de consola interactiva para el usuario
├── attacks/                   # Espacio reservado para las pruebas y capturas de red (.pcap)
├── run_server.py              # Script para arrancar el servidor
└── run_client.py              # Script para arrancar la interfaz del cliente
```

---

### 2. Integración del trabajo de Rol 1 (Fernanda) en el Servidor REST

El código original de Fernanda (`database.py`, `registro.py`, `login.py`) era local (utilizaba `input()`, `print()` y `os.system()`). Dado que la práctica exige un sistema distribuido:
1. Su fichero `database.py` se mantiene como el inicializador de las tablas (`users`, `nonces`, `transactions`).
2. La lógica criptográfica de `registro.py` (derivación con salt y 100.000 iteraciones) y de `login.py` (control de fuerza bruta con bloqueo temporal de 5 minutos tras 3 fallos) se ha integrado directamente en los endpoints `/api/v1/register` y `/api/v1/login` de `server/app.py`.
3. Al iniciar sesión con éxito, el servidor ahora genera y entrega una `session_id` y una clave de sesión de 256 bits (`session_key`), necesaria para el posterior firmado de transferencias.

---

### 3. Matriz de Requisitos de Seguridad (RS) implementados

| Requisito | Descripción | Dónde está implementado | Mecanismo técnico |
| :--- | :--- | :--- | :--- |
| **RS1.a** | Derivación robusta de contraseñas | `server/database.py` y `server/app.py` | PBKDF2-HMAC-SHA256 con 100.000 iteraciones y salt aleatorio de 16 bytes (`os.urandom(16)`). Las contraseñas nunca van en texto plano. |
| **RS1.b** | Protección contra fuerza bruta | `server/app.py` | Tras 3 intentos fallidos consecutivos, el usuario se bloquea durante 5 minutos (`locked_until`). |
| **RS2.a** | Integridad y autenticidad (HMAC) | `common/crypto_utils.py`, `client/secbank_client.py` y `server/app.py` | Firma HMAC-SHA256 calculada sobre los bytes en crudo del JSON de la transferencia e inyectada en la cabecera HTTP `X-Signature`. |
| **RS2.b** | Longitud y generación de claves | `server/app.py` | Clave de sesión efímera de 256 bits (32 bytes) generada con PRNG seguro (`secrets.token_hex(32)`). |
| **RS3.a** | Nonces y Timestamps | `common/crypto_utils.py` y `client/secbank_client.py` | Generación de Nonce único mediante UUIDv4 (`X-Nonce`) y marca de tiempo Unix actual (`X-Timestamp`). |
| **RS3.b** | Prevención de Replay (Tabla de Nonces) | `server/app.py` | El servidor rechaza peticiones con timestamp mayor a 300 s (5 min) y descarta cualquier Nonce ya registrado en la tabla `nonces` (HTTP 409 Conflict). |
| **RS4.a** | Mitigación de Timing Attacks | `server/app.py` | Validación de contraseñas y del código HMAC mediante `secrets.compare_digest()` para garantizar comparación en tiempo constante. |

---

### 4. Cómo verificar la Base de Datos (Consultas de comprobación)

Podéis comprobar el estado de la base de datos desde la terminal (en el entorno virtual activo):

#### A. Verificar que las contraseñas NO están en texto plano (RS1.a):
```bash
python -c "import sqlite3; conn = sqlite3.connect('server/secbank.db'); print(conn.cursor().execute('SELECT id, username, password_hash, salt, failed_attempts FROM users;').fetchall())"
```
*Resultado:* Se observa que el campo `password_hash` es un digest hexadecimal de 64 caracteres y que cada usuario tiene un `salt` aleatorio único asociado. La contraseña original no es legible.

#### B. Verificar las transferencias registradas con éxito (RS2 / Requisitos Funcionales):
```bash
python -c "import sqlite3; conn = sqlite3.connect('server/secbank.db'); print(conn.cursor().execute('SELECT tx_id, origin_account, destination_account, amount, currency, timestamp FROM transactions;').fetchall())"
```
*Resultado:* Muestra el historial de transacciones procesadas, con su UUIDv4, cuentas origen/destino, importe y marca de tiempo.

#### C. Verificar la tabla de Nonces consumidos (RS3.b):
```bash
python -c "import sqlite3; conn = sqlite3.connect('server/secbank.db'); print(conn.cursor().execute('SELECT nonce, timestamp FROM nonces;').fetchall())"
```
*Resultado:* Cada transferencia ejecutada deja registrado su UUID aquí para impedir que se vuelva a reproducir la misma petición.

---

### 5. Cómo arrancar el sistema para probarlo

1. **Terminal 1 (Servidor):**
   ```bash
   source .venv/bin/activate
   python run_server.py
   ```
2. **Terminal 2 (Cliente):**
   ```bash
   source .venv/bin/activate
   python run_client.py
   ```
    * Podéis hacer login con `fernanda_canales` / `F3rn4nd4_C@n@l3s#2026!SecBank`.
    * Enviar una transferencia bancaria y comprobar que el servidor responde con `SUCCESS`.

