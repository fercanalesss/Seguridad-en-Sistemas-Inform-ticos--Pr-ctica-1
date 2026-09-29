import os

existe=os.path.exists("secbank.db")
if not existe:
    print("Creando base de datos inicial")
    os.system("python database.py")

while True:
    print("\nMENU PRINCIPAL SECBANK")
    print("1 Registrar usuario")
    print("2 Iniciar sesion")
    print("3 Salir")
    opcion=input("Elige una opcion ")
    
    if opcion=="1":
        os.system("python registro.py")
    elif opcion=="2":
        os.system("python login.py")
    elif opcion=="3":
        print("Saliendo del programa")
        break
    else:
        print("Opcion no valida")
