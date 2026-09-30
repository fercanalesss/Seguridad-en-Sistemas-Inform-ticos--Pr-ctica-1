"""
secbank_client.py
Cliente HTTP para la entidad financiera SecBank.
Gestiona el transporte (Opción B: API REST sin TLS/HTTPS), el estado de sesión
y la firma de transacciones financieras.
"""

import json
from typing import Any, Dict, Optional
import uuid
import requests

from common.crypto_utils import calculate_hmac, generate_nonce, get_current_timestamp

class SecBankClient:
    """Cliente para la interacción con la API REST de SecBank."""

    def __init__(self, base_url: str = "http://127.0.0.1:8080"):
        self.base_url = base_url.rstrip("/")
        self.session_id: Optional[str] = None
        self.session_key: Optional[str] = None
        self.username: Optional[str] = None

    @property
    def is_authenticated(self) -> bool:
        """Comprueba si existe una sesión activa y válida."""
        return self.session_id is not None and self.session_key is not None

    def register(self, username: str, password: str) -> Dict[str, Any]:
        """Envía una solicitud de registro de nuevo usuario al servidor."""
        url = f"{self.base_url}/api/v1/register"
        payload = {"username": username, "password": password}
        response = requests.post(url, json=payload, timeout=5)
        return response.json()

    def login(self, username: str, password: str) -> Dict[str, Any]:
        """
        Inicia sesión y almacena el session_id y la session_key (256 bits).
        """
        url = f"{self.base_url}/api/v1/login"
        payload = {"username": username, "password": password}
        response = requests.post(url, json=payload, timeout=5)
        data = response.json()

        if response.status_code == 200 and "session_id" in data:
            self.session_id = data["session_id"]
            self.session_key = data["session_key"]
            self.username = username

        return data

    def transfer(
        self,
        origin_account: str,
        destination_account: str,
        amount: float,
        currency: str = "EUR",
    ) -> Dict[str, Any]:
        """
        Construye, firma y envía una orden de transferencia bancaria.
        Requisitos: RS2 (HMAC), RS3 (Nonce y Timestamp).
        """
        if not self.is_authenticated:
            return {"error": "No autenticado. Por favor, inicie sesión primero."}

        url = f"{self.base_url}/api/v1/transfer"

        # 1. Estructura del cuerpo según especificación
        payload = {
            "tx_id": str(uuid.uuid4()),
            "origin_account": origin_account,
            "destination_account": destination_account,
            "amount": amount,
            "currency": currency,
        }

        # 2. Serialización JSON canónica (sin espacios adicionales)
        payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        # 3. Generación de parámetros de seguridad
        nonce = generate_nonce()
        timestamp = str(get_current_timestamp())
        signature = calculate_hmac(self.session_key, payload_bytes)

        # 4. Inyección de metadatos en cabeceras HTTP personalizadas
        headers = {
            "Content-Type": "application/json",
            "X-Session-ID": self.session_id,
            "X-Nonce": nonce,
            "X-Timestamp": timestamp,
            "X-Signature": signature,
        }

        # 5. Envío de los bytes brutos en el cuerpo de la petición
        response = requests.post(url, data=payload_bytes, headers=headers, timeout=5)
        return response.json()

    def logout(self) -> Dict[str, Any]:
        """Cierra la sesión activa en el servidor y limpia el estado local."""
        if not self.is_authenticated:
            return {"message": "No hay ninguna sesión activa."}

        url = f"{self.base_url}/api/v1/logout"
        headers = {"X-Session-ID": self.session_id}

        try:
            response = requests.post(url, headers=headers, timeout=5)
            data = response.json()
        except requests.RequestException:
            data = {"message": "Servidor no disponible. Sesión local cerrada."}
        finally:
            self.session_id = None
            self.session_key = None
            self.username = None

        return data