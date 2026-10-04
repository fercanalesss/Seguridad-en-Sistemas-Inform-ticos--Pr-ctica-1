import uvicorn
#Inicia el servidor. "Server app app" es la ruta de modulo
#Esta configurado para escuchar solo por local por el puerto 8080 y para reiniciarse cada que se detectan cambios
if __name__ == "__main__":
    uvicorn.run("server.app:app", host="127.0.0.1", port=8080, reload=True)
