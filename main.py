import sqlite3
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Generator

import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from passlib.context import CryptContext
from pydantic import BaseModel

# ==========================================
# CONFIGURACIÓN Y CONSTANTES DE SEGURIDAD
# ==========================================
DB_NAME = "usuarios.db"
SECRET_KEY = "tu_super_clave_secreta_jwt_cambiala_en_produccion"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24
CODIGO_INVITACION_SECRETO = "Hakuyomi2026"

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


# ==========================================
# EJECUCIÓN DIRECTA
# ==========================================
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
