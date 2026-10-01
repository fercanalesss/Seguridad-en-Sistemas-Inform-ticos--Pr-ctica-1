import sys
import requests
import os
from client.secbank_client import SecBankClient

#Display de menu principal
def display_menu(is_authenticated: bool, username: str = None) -> None:
    print("\n" + "=" * 40)
    print("           SECBANK - CLIENTE")
    if is_authenticated:
        print(f" Estado: Autenticado como [{username}]")
    else:
        print(" Estado: No autenticado")
    print("=" * 40)

    if not is_authenticated:
        print("1. Registrar nuevo usuario")
        print("2. Iniciar sesión (Login)")
        print("3. Salir")
    else:
        print("1. Realizar transferencia bancaria")
        print("2. Cerrar sesión (Logout)")
        print("3. Salir")
    print("-" * 40)

#Registros de usuarios nuevos
def handle_register(client: SecBankClient) -> None:
    print("\n--- REGISTRO DE USUARIO ---")
    username = input("Nombre de usuario: ").strip()
    password = input("Contraseña: ").strip()
    if not username or not password:
        print("[-] Error: El usuario y la contraseña no pueden estar vacíos.")
        return
    try:
        res = client.register(username, password)
        print(f"[*] Respuesta del servidor: {res.get('message', res.get('detail', res))}")
    except requests.RequestException as exc:
        print(f"[-] Error de conexión con el servidor: {exc}")

#Login de usuarios ya existentes
def handle_login(client: SecBankClient) -> None:
    print("\n--- INICIO DE SESIÓN ---")
    username = input("Nombre de usuario: ").strip()
    password = input("Contraseña: ").strip()
    if not username or not password:
        print("[-] Error: Debe ingresar usuario y contraseña.")
        return
    try:
        res = client.login(username, password)
        if client.is_authenticated:
            print(f"[+] ¡Inicio de sesión exitoso! Bienvenido, {username}.")
        else:
            print(f"[-] Fallo en el inicio de sesión: {res.get('detail', 'Credenciales inválidas.')}")
    except requests.RequestException as exc:
        print(f"[-] Error de conexión con el servidor: {exc}")

#Realizar transferencias
def handle_transfer(client: SecBankClient) -> None:
    print("\n--- NUEVA TRANSFERENCIA BANCARIA ---")
    origin = input("Cuenta de origen (IBAN, ej. ES12345...): ").strip()
    destination = input("Cuenta de destino (IBAN, ej. ES9876...): ").strip()
    amount_str = input("Importe (ej. 1500.50): ").strip()

    try:
        amount = float(amount_str)
        if amount <= 0:
            print("[-] Error: El importe debe ser mayor que cero.")
            return
    except ValueError:
        print("[-] Error: Formato de importe no válido.")
        return

    try:
        res = client.transfer(
            origin_account=origin,
            destination_account=destination,
            amount=amount,
            currency="EUR",
        )
        if "detail" in res or "error" in res:
            print(f"[-] Transferencia rechazada: {res.get('detail', res.get('error'))}")
        else:
            print("[+] ¡Transferencia procesada con éxito!")
            print(f"    ID de transacción: {res.get('tx_id')}")
            print(f"    Estado: {res.get('status')}")
    except requests.RequestException as exc:
        print(f"[-] Error de conexión con el servidor: {exc}")


def main() -> None:
    client = SecBankClient(base_url="http://127.0.0.1:8080")
    clear_cmd = "cls" if os.name == "nt" else "clear"

    while True:
        os.system(clear_cmd)
        display_menu(client.is_authenticated, client.username)
        choice = input("Seleccione una opción: ").strip()
        os.system(clear_cmd)

        if not client.is_authenticated:
            if choice == "1":
                handle_register(client)
            elif choice == "2":
                handle_login(client)
            elif choice == "3":
                print("Saliendo del programa.")
                sys.exit(0)
            else:
                print("[-] Opción no válida.")
        else:
            if choice == "1":
                handle_transfer(client)
            elif choice == "2":
                client.logout()
                print("[+] Sesión cerrada correctamente.")
            elif choice == "3":
                client.logout()
                print("Saliendo del programa.")
                sys.exit(0)
            else:
                print("[-] Opción no válida.")
        
        if choice != "3":
            input("\nPresione Enter para continuar")


if __name__ == "__main__":
    main()