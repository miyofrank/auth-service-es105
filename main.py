import hashlib
import html
import logging
import os
import secrets
import smtplib
import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Generator

import jwt
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from pydantic import BaseModel

# ==========================================
# CONFIGURACIÓN Y CONSTANTES DE SEGURIDAD
# ==========================================
def _load_env_file(path: Path) -> None:
    """Carga variables KEY=VALUE desde un archivo .env (sin dependencias externas).
    Las variables ya definidas en el entorno del sistema tienen prioridad."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


BASE_DIR = Path(__file__).resolve().parent
_load_env_file(BASE_DIR / ".env")

logger = logging.getLogger("auth_service")
logging.basicConfig(level=logging.INFO)

DB_NAME = os.getenv("DB_NAME", "usuarios.db")
SECRET_KEY = os.getenv("SECRET_KEY", "tu_super_clave_secreta_jwt_cambiala_en_produccion")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
CODIGO_INVITACION_SECRETO = os.getenv("CODIGO_INVITACION", "Hakuyomi2026")

# Recuperación de contraseña por correo (SMTP: Gmail, Outlook, etc.)
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER)
SMTP_USE_SSL = os.getenv("SMTP_USE_SSL", "false").lower() in ("1", "true", "yes")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
RESET_TOKEN_EXPIRE_MINUTES = int(os.getenv("RESET_TOKEN_EXPIRE_MINUTES", "30"))
RESET_REQUEST_COOLDOWN_SECONDS = 60
MIN_PASSWORD_LENGTH = 8

# Contexto para hashing de contraseñas con bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ==========================================
# BASE DE DATOS (SQLite Nativo)
# ==========================================
def init_db() -> None:
    """Crea la tabla de usuarios e índices si no existen."""
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            );
            """
        )
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email);"
        )
        # Tokens de recuperación: solo se guarda el hash SHA-256, nunca el token en claro
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES usuarios(id)
            );
            """
        )
        conn.commit()


def get_db() -> Generator[sqlite3.Connection, None, None]:
    """Dependency injection para manejar conexiones seguras a SQLite."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ==========================================
# HELPERS DE SEGURIDAD (Hash y JWT)
# ==========================================
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: timedelta) -> str:
    """Genera un JWT firmado con expiración."""
    to_encode = data.copy()
    now_utc = datetime.now(timezone.utc)
    expire = now_utc + expires_delta
    to_encode.update({"iat": now_utc, "exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def hash_reset_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def smtp_configurado() -> bool:
    return bool(SMTP_HOST and SMTP_USER and SMTP_PASSWORD)


def enviar_correo_recuperacion(destinatario: str, nombre: str, enlace: str) -> None:
    """Envía el correo con el enlace de restablecimiento.
    Si no hay SMTP configurado (desarrollo), imprime el enlace en la consola."""
    if not smtp_configurado():
        logger.warning("SMTP no configurado. Enlace de recuperación para %s: %s", destinatario, enlace)
        return

    msg = EmailMessage()
    msg["Subject"] = "Restablecer contraseña - Simulador Topcon ES-105"
    msg["From"] = SMTP_FROM
    msg["To"] = destinatario
    msg.set_content(
        f"Hola {nombre},\n\n"
        "Recibimos una solicitud para restablecer la contraseña de tu cuenta del Simulador Topcon ES-105.\n\n"
        f"Abre este enlace para crear una nueva contraseña (válido por {RESET_TOKEN_EXPIRE_MINUTES} minutos):\n"
        f"{enlace}\n\n"
        "Si no solicitaste este cambio, ignora este correo; tu contraseña seguirá igual.\n"
    )
    msg.add_alternative(
        f"""<div style="font-family:Arial,sans-serif;color:#26231E;max-width:480px">
  <h2 style="color:#945F03">Simulador Topcon ES-105</h2>
  <p>Hola {html.escape(nombre)},</p>
  <p>Recibimos una solicitud para restablecer la contraseña de tu cuenta.</p>
  <p><a href="{enlace}" style="display:inline-block;background:#D99414;color:#fff;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:bold">Crear nueva contraseña</a></p>
  <p style="font-size:12px;color:#6B6355">El enlace vence en {RESET_TOKEN_EXPIRE_MINUTES} minutos. Si no solicitaste este cambio, ignora este correo.</p>
</div>""",
        subtype="html",
    )

    try:
        if SMTP_USE_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        logger.info("Correo de recuperación enviado a %s", destinatario)
    except Exception:  # noqa: BLE001 - se registra y no se expone al cliente
        logger.exception("Error enviando correo de recuperación a %s", destinatario)


# ==========================================
# ESQUEMAS DE VALIDACIÓN (Pydantic)
# ==========================================
class RegisterRequest(BaseModel):
    nombre: str
    email: str
    password: str
    codigo_invitacion: str


class LoginRequest(BaseModel):
    email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    nombre: str


class MessageResponse(BaseModel):
    mensaje: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str


# ==========================================
# CICLO DE VIDA Y APLICACIÓN FASTAPI
# ==========================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: Inicializar la base de datos automáticamente
    init_db()
    yield


app = FastAPI(
    title="Microservicio de Autenticación Local",
    version="1.0.0",
    lifespan=lifespan,
)

# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==========================================
# ENDPOINTS
# ==========================================
@app.post(
    "/api/register",
    response_model=MessageResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registro de nuevos usuarios",
)
def register(user_data: RegisterRequest, db: sqlite3.Connection = Depends(get_db)):
    # 1. Validación de código de invitación secreto
    if user_data.codigo_invitacion != CODIGO_INVITACION_SECRETO:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Código de invitación inválido",
        )

    clean_email = user_data.email.strip().lower()
    cursor = db.cursor()

    # 2. Verificar que el email no exista en la DB
    cursor.execute("SELECT id FROM usuarios WHERE email = ?", (clean_email,))
    if cursor.fetchone():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El email ya se encuentra registrado",
        )

    # 3. Hashear contraseña y persistir en SQLite
    hashed_password = get_password_hash(user_data.password)

    cursor.execute(
        """
        INSERT INTO usuarios (nombre, email, password_hash)
        VALUES (?, ?, ?)
        """,
        (user_data.nombre.strip(), clean_email, hashed_password),
    )
    db.commit()

    return MessageResponse(mensaje="Usuario registrado exitosamente")


@app.post(
    "/api/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Inicio de sesión y emisión de JWT",
)
def login(credentials: LoginRequest, db: sqlite3.Connection = Depends(get_db)):
    clean_email = credentials.email.strip().lower()

    cursor = db.cursor()
    cursor.execute(
        "SELECT id, nombre, email, password_hash FROM usuarios WHERE email = ?",
        (clean_email,),
    )
    user = cursor.fetchone()

    # Validación conjunta para mitigar ataques de temporización
    if not user or not verify_password(credentials.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Generación del token con vigencia de 24 horas
    token_payload = {
        "sub": str(user["id"]),
        "email": user["email"],
        "nombre": user["nombre"],
    }
    token = create_access_token(
        data=token_payload,
        expires_delta=timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS),
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        nombre=user["nombre"],
    )


MENSAJE_RECUPERACION = (
    "Si el correo está registrado, recibirás un enlace para restablecer tu contraseña en unos minutos."
)


@app.post(
    "/api/forgot-password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Solicitar enlace de recuperación de contraseña",
)
def forgot_password(
    data: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    db: sqlite3.Connection = Depends(get_db),
):
    clean_email = data.email.strip().lower()
    cursor = db.cursor()
    cursor.execute("SELECT id, nombre, email FROM usuarios WHERE email = ?", (clean_email,))
    user = cursor.fetchone()

    # Respuesta idéntica exista o no el correo (evita revelar qué emails están registrados)
    if not user:
        return MessageResponse(mensaje=MENSAJE_RECUPERACION)

    now_utc = datetime.now(timezone.utc)

    # Anti-spam: no reenviar si ya se pidió un enlace hace menos de 60 segundos
    cursor.execute(
        "SELECT created_at FROM password_resets WHERE user_id = ? ORDER BY id DESC LIMIT 1",
        (user["id"],),
    )
    ultimo = cursor.fetchone()
    if ultimo and (now_utc - datetime.fromisoformat(ultimo["created_at"])).total_seconds() < RESET_REQUEST_COOLDOWN_SECONDS:
        return MessageResponse(mensaje=MENSAJE_RECUPERACION)

    # Invalidar enlaces anteriores y generar uno nuevo
    cursor.execute("UPDATE password_resets SET used = 1 WHERE user_id = ? AND used = 0", (user["id"],))
    token = secrets.token_urlsafe(32)
    expires = now_utc + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)
    cursor.execute(
        """
        INSERT INTO password_resets (user_id, token_hash, created_at, expires_at, used)
        VALUES (?, ?, ?, ?, 0)
        """,
        (user["id"], hash_reset_token(token), now_utc.isoformat(), expires.isoformat()),
    )
    db.commit()

    enlace = f"{FRONTEND_URL}/?reset_token={token}"
    background_tasks.add_task(enviar_correo_recuperacion, user["email"], user["nombre"], enlace)

    return MessageResponse(mensaje=MENSAJE_RECUPERACION)


@app.post(
    "/api/reset-password",
    response_model=MessageResponse,
    status_code=status.HTTP_200_OK,
    summary="Restablecer contraseña con el token recibido por correo",
)
def reset_password(data: ResetPasswordRequest, db: sqlite3.Connection = Depends(get_db)):
    if len(data.new_password) < MIN_PASSWORD_LENGTH:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"La contraseña debe tener al menos {MIN_PASSWORD_LENGTH} caracteres",
        )

    cursor = db.cursor()
    cursor.execute(
        "SELECT id, user_id, expires_at, used FROM password_resets WHERE token_hash = ?",
        (hash_reset_token(data.token.strip()),),
    )
    registro = cursor.fetchone()

    if (
        not registro
        or registro["used"]
        or datetime.fromisoformat(registro["expires_at"]) < datetime.now(timezone.utc)
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El enlace de recuperación no es válido o ya expiró. Solicita uno nuevo.",
        )

    cursor.execute(
        "UPDATE usuarios SET password_hash = ? WHERE id = ?",
        (get_password_hash(data.new_password), registro["user_id"]),
    )
    cursor.execute("UPDATE password_resets SET used = 1 WHERE user_id = ?", (registro["user_id"],))
    db.commit()

    return MessageResponse(mensaje="Contraseña actualizada. Ya puedes iniciar sesión con tu nueva contraseña.")


# ==========================================
# EJECUCIÓN DIRECTA
# ==========================================
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
