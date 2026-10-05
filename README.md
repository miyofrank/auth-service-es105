# Microservicio de Autenticación Local

Microservicio ligero y seguro de autenticación en Python desarrollado con **FastAPI**, **SQLite**, **passlib** (bcrypt) y **PyJWT**.

## 🚀 Características
- **FastAPI**: Endpoints rápidos, asíncronos y con documentación Swagger automática (`/docs`).
- **SQLite nativo**: Sin sobrecarga de ORM, inicialización automática al arrancar.
- **Passlib & Bcrypt**: Hash seguro de contraseñas.
- **PyJWT**: Emisión y validación de tokens JWT con 24 horas de vigencia.
- **CORS Habilitado**: Configurado para desarrollo frontend sin bloqueos.

---

## 📋 Endpoints

### 1. `POST /api/register`
Registra un nuevo usuario en la base de datos si el código de invitación es válido.
- **Body JSON:**
  ```json
  {
    "nombre": "Frank Cruz",
    "email": "usuario@ejemplo.com",
    "password": "tu_password_seguro",
    "codigo_invitacion": "Hakuyomi2026"
  }
  ```
- **Respuestas:**
  - `201 Created`: Usuario creado exitosamente.
  - `400 Bad Request`: Email ya registrado.
  - `403 Forbidden`: Código de invitación inválido.

### 2. `POST /api/login`
Autentica al usuario y retorna un token JWT bearer válido por 24 horas.
- **Body JSON:**
  ```json
  {
    "email": "usuario@ejemplo.com",
    "password": "tu_password_seguro"
  }
  ```
- **Respuestas:**
  - `200 OK`:
    ```json
    {
      "access_token": "<jwt_token>",
      "token_type": "bearer",
      "nombre": "Frank Cruz"
    }
    ```
  - `401 Unauthorized`: Credenciales inválidas.

---

## 🛠️ Instalación y Ejecución

```bash
# 1. Crear y activar entorno virtual
python -m venv .venv
source .venv/bin/activate  # En Linux/Mac
.\.venv\Scripts\Activate.ps1  # En Windows PowerShell

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Iniciar el servicio
uvicorn main:app --reload --port 8000
```

Documentación interactiva disponible en: `http://localhost:8000/docs`
