Pasos para el correcto funcionamiento de servidor, cliente y base de datos:

Instalar todas las dependencias con el siguiente comando:

	pip install -r requirements.txt

Antes de arrancar el servidor asegurarse de que la base de datos existe, entrar a la carpeta server y ejecutar en la terminal:

	python database.py

Arrancar el servidor en la carpeta raiz, abrir una terminal y ejecutar el siguiente comando:

	python run_server.py

IMPORTANTE: NO CERRAR ESA TERMINAL


Arrancar el cliente, EN UNA TERMINAL NUEVA de la misma manera que el servidor, ejecutar el siguiente comando:

	python run_client.py

Si todo funciono de manera correcta ya se puede usar el Sistema para hacer pruebas y ver como responde el servidor. En caso de querer realizar ataques, en otra terminal ejecutar:

	python ataques.py

-----------------------
Pruebas con Wireshark
-----------------------
Abre Wireshark
Selecciona la interfaz de red local:

Windows: Adapter for loopback traffic capture
Linux/Mac: lo o loopback

En la barra de filtro escribir:

	tcp.port == 8080 and http 

****NOTA IMPORTANTE: para ver la evidencia en el archivo de wireshark que corresponde al Proyecto es importante Tambien escribir la linea anterior para filtrar solo lo que corresponde al proyecto****

Iniciar captura
Ejecuta el script de ataques o interactua normalmente con el cliente

A. Evidencia de Bloqueo por Firma Invalida / MitM (HTTP 401)

	Busca la peticion POST donde se altero el monto a 9999.0 EUR
	Haz clic derecho sobre la peticion -> Follow > TCP Stream
	Observa en rojo el envio del JSON alterado con la firma original, y en azul la respuesta del servidor con un error HTTP 401 (Fallo de integridad: 	HMAC no coincide)

B. Evidencia de Bloqueo Replay / Nonce Duplicado (HTTP 409 / 400)

	Localiza las dos peticiones identicas
	La primera devuelve HTTP 200 OK y la segunda es rechazada inmediatamente con un error HTTP 409

-----------------------
Pruebas con Db Browser
-----------------------

Asegurarse de que la base de datos ya existe
Abre DB Browser for SQLite

Haz clic en Open database.
Selecciona el archivo secbank.db dentro de la carpeta server/
Ve a la pestaña Browse data

A. Tabla users (Proteccion de Credenciales y Fuerza Bruta)

	Selecciona la tabla users
	Verificacion de Hashing (RS1.a):
	Observa la columna password_hash
	Las contraseñas no estan en texto plano, sino convertidas en cadenas hexadecimales derivadas con PBKDF2-HMAC-SHA256.
	la columna salt, cada usuario tiene un valor hexadecimal aleatorio e independiente de 16 bytes

	Verificacion de Bloqueo:
	Buscar usuario objetivo del ataque de fuerza bruta
	La columna failed_attempts refleja 3 intentos fallidos
	La columna locked_until contiene la marca de tiempo exacta de bloqueo (5 minutos)

B. Tabla nonces (Proteccion Anti-Replay)

	Selecciona la tabla nonces
	Contiene la lista de nonces y sus respectivos timestamps

C. Tabla transactions (Integridad del Almacenamiento)

	Selecciona la tabla transactions
	Comprueba las operaciones registradas:
	Veras únicamente la transacción legítima de 100.0 EUR.
	Confirma que NO existe ninguna transacción por 9999.0 EUR (ataque MitM) ni transacciones duplicadas (ataque Replay)