import requests #libreria para enviar peticiones al servidor
import uuid #libreria para generar identificadores para las transferencias
import time 
import json
#Librerias para generar y validar firmas hmac-sha256
import hmac
import hashlib

BASE_URL = "http://127.0.0.1:8080/api/v1" #Almacenar direccion del API Rest

# Usuarios: El primero sera para simular un login correcto, si se cambia solo revisar que el password sea correcto
USER_AUTH = "erick_villalobos"
PASS_AUTH = "ErickVi14!#"
USER_BRUTE = "sonja_hohmann" #usuario que se usa para simular fuerza bruta

def print_header(title):
    print(f"\n{'='*70}")
    print(f" {title}")
    print(f"{'='*70}")

#Calcular firma de un diccionario
def calcular_firma(session_key, payload_dict):
    payload_bytes = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8") #Convertir el diccionario en una cadena JSON y la transforma a utf-8
    key_bytes = bytes.fromhex(session_key) #Convierte la clave de hexadecimal a bytes
    return hmac.new(key_bytes, payload_bytes, hashlib.sha256).hexdigest()

def simular_ataques():
    #Iniciar sesion de manera legitima con uno de los usuarios de prueba, el ususario y password estan mas arriba
    print_header("Login en erick_villalobos")
    res = requests.post(f"{BASE_URL}/login", json={"username": USER_AUTH, "password": PASS_AUTH})

    #Comprobar si el estado es 200 (OK), si no se devuelve un error y no se inicia sesion
    if res.status_code != 200:
        print("Error")
        return
        
    data = res.json()
    session_id = data["session_id"]
    session_key = data["session_key"]
    print(f"Login exitoso para {USER_AUTH}.")
    print(f"    Session ID: {session_id}")
    print(f"    Session Key: {session_key[:10]}... 256-bits ocultos")

    print_header("Ataque por fuerza bruta")
    print("Se intenta adivinar el password")
    #Ciclo for para enviar passwords incorrectos y bloquear el usuario
    #no se estan enviando passwords al azar solo se esta enviando el usuario con el password incorrecto para simular un intento de adivinar
    for i in range(1, 5):
        r = requests.post(f"{BASE_URL}/login", json={"username": USER_BRUTE, "password": "1234"})
        if r.status_code == 401: #El codigo 401 significa que el intento es fallido, no que la cuenta esta bloqueada
            print(f"    Intento {i} -> Bloqueado (HTTP 401): {r.json().get('detail')}")
        elif r.status_code == 403: #El codigo 403 si representa que la cuenta esta bloqueada
            print(f"    Intento {i} -> CUENTA BLOQUEADA (HTTP 403): {r.json().get('detail')}")


    print_header("Man in the middle")
    #Aqui se generan identificadores, nonce y timestamp
    nonce = str(uuid.uuid4())
    timestamp = str(int(time.time()))

    #Datos para transferencia CORRECTA de 50 euros
    datos_original = {
        "tx_id": str(uuid.uuid4()),
        "origin_account": "ES1111",
        "destination_account": "ES9999",
        "amount": 50.0,
        "currency": "EUR"
    }
    #Calcular la firma de la transferencia anterior que es de 50 EUR
    signature = calcular_firma(session_key, datos_original)
    datos_alterada = datos_original.copy()
    datos_alterada["amount"] = 9999.0 #Modificar la cantidad enviada sin actualizar la firma a 9999 EUR
    payload_bytes_alterado = json.dumps(datos_alterada, separators=(",", ":")).encode("utf-8") #Se mete todo en json y se convierte en bytes

    #Cabeceras
    headers_mitm = {
        "Content-Type": "application/json",
        "X-Session-ID": session_id,
        "X-Nonce": nonce,
        "X-Timestamp": timestamp,
        "X-Signature": signature
    }
    
    print("Alterando el monto de la transferencia a 9999.0 EUR")
    #Envio de la peticion alterada con firma original de 50 EUR
    #Se debe notar los datos estan siendo alterados por que la firm no coincide
    r2 = requests.post(f"{BASE_URL}/transfer", data=payload_bytes_alterado, headers=headers_mitm)
    print(f"    Resultado -> Rechazado (HTTP {r2.status_code}): {r2.json().get('detail')}")


    print_header("Replays")
    #Datos para una transferencia valida de 100 EUR
    datos_valido = {
        "tx_id": str(uuid.uuid4()),
        "origin_account": "ES1111",
        "destination_account": "ES9999",
        "amount": 100.0,
        "currency": "EUR"
    }
    nonce_valido = str(uuid.uuid4())
    timestamp_valido = str(int(time.time()))
    sig_valido = calcular_firma(session_key, datos_valido)
    payload_valido = json.dumps(datos_valido, separators=(",", ":")).encode("utf-8")
    
    headers_validos = {
        "Content-Type": "application/json",
        "X-Session-ID": session_id,
        "X-Nonce": nonce_valido,
        "X-Timestamp": timestamp_valido,
        "X-Signature": sig_valido
    }
    
    print("Transfiriendo 100 euros de manera correcta")
    # se hace la transferencia de manera correcta. En DB browser debe aparecer junto con su nonce
    r3_a = requests.post(f"{BASE_URL}/transfer", data=payload_valido, headers=headers_validos)
    print(f"    Resultado -> Aceptada (HTTP {r3_a.status_code})")

    #Se reenvia exactamente la misma peticion pero el nonce ya existe por lo que deberia bloquearse al consultar la base de datos
    print("Envio de transferecia identica")
    r3_b = requests.post(f"{BASE_URL}/transfer", data=payload_valido, headers=headers_validos)
    print(f"    Resultado -> Rechazado (HTTP {r3_b.status_code}): {r3_b.json().get('detail')}")


    print_header("Timestamp")
    #se crea nuevamente una transferencia valida
    datos_viejos = {
        "tx_id": str(uuid.uuid4()),
        "origin_account": "ES1111",
        "destination_account": "ES9999",
        "amount": 200.0,
        "currency": "EUR"
    }
    nonce_nuevo = str(uuid.uuid4())
    #Se restan 600 segundos a la hora actual para simular un paquete viejo
    timestamp_expirado = str(int(time.time()) - 600) 
    sig_viejos = calcular_firma(session_key, datos_viejos)
    payload_viejo = json.dumps(datos_viejos, separators=(",", ":")).encode("utf-8")
    
    headers_viejos = {
        "Content-Type": "application/json",
        "X-Session-ID": session_id,
        "X-Nonce": nonce_nuevo,
        "X-Timestamp": timestamp_expirado,
        "X-Signature": sig_viejos
    }
    
    print(f"Enviando timestamp de hace 10 minutos")
    #El servidor debe restar el tiemstamp con la hora actual
    #Al restar debe poder calcular que paso tiempo  y rechazar la operacion
    r4 = requests.post(f"{BASE_URL}/transfer", data=payload_viejo, headers=headers_viejos)
    print(f"    Resultado -> Rechazado (HTTP {r4.status_code}): {r4.json().get('detail')}\n")

if __name__ == "__main__":
    simular_ataques()
