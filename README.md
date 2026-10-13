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

### 3. `POST /api/forgot-password`
Genera un enlace de recuperación (válido 30 min) y lo envía al correo del usuario.
- **Body JSON:** `{ "email": "usuario@ejemplo.com" }`
- **Respuesta:** `200 OK` siempre con el mismo mensaje, exista o no el correo (no revela qué emails están registrados).
- Si se pide otro enlace antes de 60 s, no se reenvía. Pedir uno nuevo invalida los anteriores.
- Si el SMTP no está configurado, el enlace se imprime en la consola del servidor (útil en desarrollo).

### 4. `POST /api/reset-password`
Cambia la contraseña con el token del enlace.
- **Body JSON:** `{ "token": "<token del enlace>", "new_password": "minimo8caracteres" }`
- **Respuestas:**
  - `200 OK`: Contraseña actualizada.
  - `400 Bad Request`: Token inválido, usado o vencido, o contraseña de menos de 8 caracteres.

En la base de datos solo se guarda el hash SHA-256 del token, nunca el token en claro.

---

## ✉️ Configuración del correo (`.env`)

1. Copia `.env.example` como `.env` en la misma carpeta que `main.py`.
2. Completa `FRONTEND_URL` con la URL pública del simulador en la VM (el enlace del correo apunta ahí).
3. Gmail: activa la verificación en 2 pasos de la cuenta y crea una **contraseña de aplicación** en https://myaccount.google.com/apppasswords. Úsala en `SMTP_PASSWORD` (16 caracteres, sin espacios). La contraseña normal de Gmail no funciona.
4. Reinicia el servicio.

`.env` ya está en `.gitignore`: no se sube al repositorio.

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
