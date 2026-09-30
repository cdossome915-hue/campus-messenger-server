import os
import uuid
import secrets
import hashlib
import sqlite3
from datetime import datetime, timedelta, timezone

from fastapi import FastAPI, HTTPException, Header, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# ============================================================
# CAMPUS MESSENGER - SERVEUR
# Fichier unique : server.py
# ============================================================

app = FastAPI(
    title="Campus Messenger",
    version="1.0.0"
)

# ------------------------------------------------------------
# CORS
# ------------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------------------------------------------------
# CONFIGURATION
# ------------------------------------------------------------

PORT = int(os.environ.get("PORT", "10000"))

DATABASE = os.environ.get(
    "DATABASE",
    "campus.db"
)

# En production, mets une vraie valeur secrète
SECRET = os.environ.get(
    "SECRET_KEY",
    "CHANGE_THIS_SECRET_IN_RENDER"
)

# ------------------------------------------------------------
# BASE DE DONNÉES
# ------------------------------------------------------------

def db():
    connection = sqlite3.connect(
        DATABASE,
        check_same_thread=False
    )

    connection.row_factory = sqlite3.Row

    return connection


def init_database():

    connection = db()

    connection.executescript("""

    CREATE TABLE IF NOT EXISTS users (

        id TEXT PRIMARY KEY,

        public_code TEXT UNIQUE NOT NULL,

        username TEXT UNIQUE NOT NULL,

        password_hash TEXT NOT NULL,

        display_name TEXT NOT NULL,

        avatar TEXT DEFAULT '',

        bio TEXT DEFAULT '',

        created_at TEXT NOT NULL,

        last_seen TEXT,

        online INTEGER DEFAULT 0,

        allow_messages INTEGER DEFAULT 1,

        allow_calls INTEGER DEFAULT 1,

        show_online INTEGER DEFAULT 1,

        show_last_seen INTEGER DEFAULT 1
    );


    CREATE TABLE IF NOT EXISTS contacts (

        user_id TEXT NOT NULL,

        contact_id TEXT NOT NULL,

        created_at TEXT NOT NULL,

        PRIMARY KEY(user_id, contact_id)
    );


    CREATE TABLE IF NOT EXISTS messages (

        id TEXT PRIMARY KEY,

        sender_id TEXT NOT NULL,

        receiver_id TEXT NOT NULL,

        body TEXT NOT NULL,

        created_at TEXT NOT NULL,

        read_at TEXT
    );


    CREATE INDEX IF NOT EXISTS messages_index

    ON messages(
        sender_id,
        receiver_id,
        created_at
    );

    """)

    connection.commit()

    connection.close()


init_database()

# ------------------------------------------------------------
# OUTILS
# ------------------------------------------------------------

def now():

    return datetime.now(
        timezone.utc
    ).isoformat()


def hash_password(password):

    salt = secrets.token_bytes(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        200000
    )

    return (
        salt.hex()
        + ":"
        + password_hash.hex()
    )


def check_password(password, stored):

    try:

        salt_hex, hash_hex = stored.split(":")

        salt = bytes.fromhex(
            salt_hex
        )

        expected = bytes.fromhex(
            hash_hex
        )

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode(),
            salt,
            200000
        )

        return secrets.compare_digest(
            actual,
            expected
        )

    except Exception:

        return False


# ------------------------------------------------------------
# IDENTIFIANT PUBLIC
# ------------------------------------------------------------

def generate_public_code():

    alphabet = (
        "ABCDEFGHJKLMNPQRSTUVWXYZ"
        "23456789"
    )

    while True:

        code = "MALI-"

        for i in range(8):

            code += secrets.choice(
                alphabet
            )

            if i == 3:

                code += "-"

        connection = db()

        exists = connection.execute(
            """
            SELECT id
            FROM users
            WHERE public_code = ?
            """,
            (code,)
        ).fetchone()

        connection.close()

        if not exists:

            return code


# ------------------------------------------------------------
# TOKENS
# ------------------------------------------------------------

tokens = {}


def create_token(user_id):

    token = secrets.token_urlsafe(48)

    tokens[token] = {
        "user_id": user_id,
        "created": datetime.now(
            timezone.utc
        )
    }

    return token


def get_user_from_token(token):

    if not token:

        return None

    data = tokens.get(token)

    if not data:

        return None

    return data["user_id"]


def require_auth(
    authorization: str | None
):

    if not authorization:

        raise HTTPException(
            status_code=401,
            detail="Authentification requise"
        )

    if not authorization.startswith(
        "Bearer "
    ):

        raise HTTPException(
            status_code=401,
            detail="Token invalide"
        )

    token = authorization[7:]

    user_id = get_user_from_token(
        token
    )

    if not user_id:

        raise HTTPException(
            status_code=401,
            detail="Session invalide"
        )

    return user_id


# ------------------------------------------------------------
# UTILISATEUR PUBLIC
# ------------------------------------------------------------

def public_user(user):

    return {

        "id": user["id"],

        "code": user["public_code"],

        "username": user["username"],

        "displayName":
            user["display_name"],

        "avatar":
            user["avatar"],

        "bio":
            user["bio"],

        "online":
            bool(user["online"])
            if user["show_online"]
            else False,

        "lastSeen":
            user["last_seen"]
            if user["show_last_seen"]
            else None
    }


# ------------------------------------------------------------
# MODÈLES
# ------------------------------------------------------------

class Register(BaseModel):

    username: str = Field(
        min_length=3,
        max_length=40
    )

    password: str = Field(
        min_length=8,
        max_length=200
    )

    displayName: str = Field(
        min_length=1,
        max_length=80
    )


class Login(BaseModel):

    username: str

    password: str


class UpdateProfile(BaseModel):

    displayName: str | None = None

    avatar: str | None = None

    bio: str | None = None

    allowMessages: bool | None = None

    allowCalls: bool | None = None

    showOnline: bool | None = None

    showLastSeen: bool | None = None


class AddContact(BaseModel):

    code: str


class SendMessage(BaseModel):

    receiverId: str

    text: str = Field(
        min_length=1,
        max_length=4000
    )


# ------------------------------------------------------------
# SERVEUR
# ------------------------------------------------------------

@app.get("/")
def home():

    return {

        "application":
            "Campus Messenger",

        "status":
            "online",

        "version":
            "1.0.0"
    }


@app.get("/health")
def health():

    try:

        connection = db()

        connection.execute(
            "SELECT 1"
        )

        connection.close()

        return {

            "server": "ok",

            "database": "ok"
        }

    except Exception:

        raise HTTPException(
            status_code=503,
            detail="Database unavailable"
        )


# ------------------------------------------------------------
# CRÉER UN COMPTE
# ------------------------------------------------------------

@app.post("/api/register")
def register(data: Register):

    username = data.username.strip()

    display_name = (
        data.displayName.strip()
    )

    if not username:

        raise HTTPException(
            400,
            "Nom utilisateur invalide"
        )

    connection = db()

    exists = connection.execute(
        """
        SELECT id
        FROM users
        WHERE LOWER(username)
        = LOWER(?)
        """,
        (username,)
    ).fetchone()

    if exists:

        connection.close()

        raise HTTPException(
            409,
            "Ce nom utilisateur existe déjà"
        )

    user_id = str(
        uuid.uuid4()
    )

    public_code = (
        generate_public_code()
    )

    password_hash = hash_password(
        data.password
    )

    connection.execute(
        """
        INSERT INTO users (

            id,

            public_code,

            username,

            password_hash,

            display_name,

            created_at
        )

        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            user_id,

            public_code,

            username,

            password_hash,

            display_name,

            now()
        )
    )

    connection.commit()

    connection.close()

    token = create_token(
        user_id
    )

    return {

        "success": True,

        "token": token,

        "user": {

            "id": user_id,

            "code": public_code,

            "username": username,

            "displayName":
                display_name
        }
    }


# ------------------------------------------------------------
# CONNEXION
# ------------------------------------------------------------

@app.post("/api/login")
def login(data: Login):

    connection = db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE LOWER(username)
        = LOWER(?)
        """,
        (data.username,)
    ).fetchone()

    connection.close()

    if not user:

        raise HTTPException(
            401,
            "Identifiants incorrects"
        )

    if not check_password(
        data.password,
        user["password_hash"]
    ):

        raise HTTPException(
            401,
            "Identifiants incorrects"
        )

    token = create_token(
        user["id"]
    )

    return {

        "success": True,

        "token": token,

        "user":
            public_user(user)
    }


# ------------------------------------------------------------
# MON PROFIL
# ------------------------------------------------------------

@app.get("/api/me")
def me(
    authorization:
    str | None = Header(default=None)
):

    user_id = require_auth(
        authorization
    )

    connection = db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (user_id,)
    ).fetchone()

    connection.close()

    if not user:

        raise HTTPException(
            404,
            "Utilisateur introuvable"
        )

    return {
        "user":
            public_user(user)
    }


# ------------------------------------------------------------
# MODIFIER PROFIL
# ------------------------------------------------------------

@app.patch("/api/me")
def update_me(
    data: UpdateProfile,
    authorization:
    str | None = Header(default=None)
):

    user_id = require_auth(
        authorization
    )

    connection = db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id=?
        """,
        (user_id,)
    ).fetchone()

    if not user:

        connection.close()

        raise HTTPException(
            404,
            "Utilisateur introuvable"
        )

    connection.execute(
        """
        UPDATE users

        SET

        display_name = ?,

        avatar = ?,

        bio = ?,

        allow_messages = ?,

        allow_calls = ?,

        show_online = ?,

        show_last_seen = ?

        WHERE id=?
        """,
        (

            data.displayName
            if data.displayName is not None
            else user["display_name"],

            data.avatar
            if data.avatar is not None
            else user["avatar"],

            data.bio
            if data.bio is not None
            else user["bio"],

            int(
                data.allowMessages
                if data.allowMessages
                is not None
                else user["allow_messages"]
            ),

            int(
                data.allowCalls
                if data.allowCalls
                is not None
                else user["allow_calls"]
            ),

            int(
                data.showOnline
                if data.showOnline
                is not None
                else user["show_online"]
            ),

            int(
                data.showLastSeen
                if data.showLastSeen
                is not None
                else user["show_last_seen"]
            ),

            user_id
        )
    )

    connection.commit()

    updated = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id=?
        """,
        (user_id,)
    ).fetchone()

    connection.close()

    return {
        "user":
            public_user(updated)
    }


# ------------------------------------------------------------
# RECHERCHER UN UTILISATEUR
# ------------------------------------------------------------

@app.get("/api/users/code/{code}")
def find_user(
    code: str,
    authorization:
    str | None = Header(default=None)
):

    require_auth(
        authorization
    )

    connection = db()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE public_code=?
        """,
        (code.upper(),)
    ).fetchone()

    connection.close()

    if not user:

        raise HTTPException(
            404,
            "Utilisateur introuvable"
        )

    return {
        "user":
            public_user(user)
    }


# ------------------------------------------------------------
# AJOUTER CONTACT
# ------------------------------------------------------------

@app.post("/api/contacts")
def add_contact(
    data: AddContact,
    authorization:
    str | None = Header(default=None)
):

    user_id = require_auth(
        authorization
    )

    code = data.code.upper().strip()

    connection = db()

    contact = connection.execute(
        """
        SELECT *
        FROM users
        WHERE public_code=?
        """,
        (code,)
    ).fetchone()

    if not contact:

        connection.close()

        raise HTTPException(
            404,
            "Utilisateur introuvable"
        )

    if contact["id"] == user_id:

        connection.close()

        raise HTTPException(
            400,
            "Impossible de vous ajouter"
        )

    if not contact[
        "allow_messages"
    ]:

        connection.close()

        raise HTTPException(
            403,
            "Cet utilisateur n'accepte pas les messages"
        )

    connection.execute(
        """
        INSERT OR IGNORE INTO contacts
        (
            user_id,
            contact_id,
            created_at
        )

        VALUES (?, ?, ?)
        """,
        (
            user_id,

            contact["id"],

            now()
        )
    )

    connection.commit()

    connection.close()

    return {

        "success": True,

        "contact":
            public_user(contact)
    }


# ------------------------------------------------------------
# LISTE CONTACTS
# ------------------------------------------------------------

@app.get("/api/contacts")
def contacts(
    authorization:
    str | None = Header(default=None)
):

    user_id = require_auth(
        authorization
    )

    connection = db()

    rows = connection.execute(
        """
        SELECT u.*

        FROM contacts c

        JOIN users u
        ON u.id=c.contact_id

        WHERE c.user_id=?

        ORDER BY u.display_name
        """,
        (user_id,)
    ).fetchall()

    connection.close()

    return {

        "contacts":
            [
                public_user(user)
                for user in rows
            ]
    }


# ------------------------------------------------------------
# HISTORIQUE MESSAGES
# ------------------------------------------------------------

@app.get(
    "/api/messages/{other_user_id}"
)
def message_history(
    other_user_id: str,

    authorization:
    str | None = Header(default=None)
):

    user_id = require_auth(
        authorization
    )

    connection = db()

    relation = connection.execute(
        """
        SELECT 1
        FROM contacts
        WHERE user_id=?
        AND contact_id=?
        """,
        (
            user_id,
            other_user_id
        )
    ).fetchone()

    if not relation:

        connection.close()

        raise HTTPException(
            403,
            "Vous devez être contacts"
        )

    rows = connection.execute(
        """
        SELECT
            id,
            sender_id,
            receiver_id,
            body,
            created_at,
            read_at

        FROM messages

        WHERE
        (
            sender_id=?
            AND receiver_id=?
        )

        OR

        (
            sender_id=?
            AND receiver_id=?
        )

        ORDER BY created_at ASC

        LIMIT 500
        """,
        (
            user_id,
            other_user_id,

            other_user_id,
            user_id
        )
    ).fetchall()

    connection.close()

    return {

        "messages":
            [
                dict(row)
                for row in rows
            ]
    }


# ------------------------------------------------------------
# UTILISATEURS CONNECTÉS
# ------------------------------------------------------------

connected_users = {}


# ------------------------------------------------------------
# WEBSOCKET
# ------------------------------------------------------------

@app.websocket("/ws")
async def websocket(
    websocket: WebSocket
):

    token = websocket.query_params.get(
        "token"
    )

    user_id = get_user_from_token(
        token
    )

    if not user_id:

        await websocket.close(
            code=1008
        )

        return

    await websocket.accept()

    connected_users[
        user_id
    ] = websocket

    connection = db()

    connection.execute(
        """
        UPDATE users

        SET

        online=1,

        last_seen=?

        WHERE id=?
        """,
        (
            now(),

            user_id
        )
    )

    connection.commit()

    connection.close()

    try:

        while True:

            data = await websocket.receive_json()

            event = data.get(
                "event"
            )

            # ------------------------------------------------
            # MESSAGE
            # ------------------------------------------------

            if event == "message":

                receiver_id = data.get(
                    "receiverId"
                )

                text = str(
                    data.get("text", "")
                ).strip()

                if not text:

                    continue

                if len(text) > 4000:

                    continue

                connection = db()

                relation = connection.execute(
                    """
                    SELECT 1
                    FROM contacts

                    WHERE user_id=?
                    AND contact_id=?
                    """,
                    (
                        user_id,
                        receiver_id
                    )
                ).fetchone()

                if not relation:

                    connection.close()

                    await websocket.send_json({
                        "event":
                            "error",

                        "message":
                            "Contact non autorisé"
                    })

                    continue

                receiver = connection.execute(
                    """
                    SELECT allow_messages
                    FROM users
                    WHERE id=?
                    """,
                    (receiver_id,)
                ).fetchone()

                if not receiver:

                    connection.close()

                    continue

                if not receiver[
                    "allow_messages"
                ]:

                    connection.close()

                    continue

                message_id = str(
                    uuid.uuid4()
                )

                created = now()

                connection.execute(
                    """
                    INSERT INTO messages

                    (
                        id,
                        sender_id,
                        receiver_id,
                        body,
                        created_at
                    )

                    VALUES
                    (?, ?, ?, ?, ?)
                    """,
                    (
                        message_id,

                        user_id,

                        receiver_id,

                        text,

                        created
                    )
                )

                connection.commit()

                connection.close()

                message = {

                    "event":
                        "message",

                    "id":
                        message_id,

                    "senderId":
                        user_id,

                    "receiverId":
                        receiver_id,

                    "text":
                        text,

                    "createdAt":
                        created
                }

                receiver_socket = (
                    connected_users.get(
                        receiver_id
                    )
                )

                if receiver_socket:

                    await receiver_socket.send_json(
                        message
                    )

                await websocket.send_json(
                    message
                )

            # ------------------------------------------------
            # WEBRTC : APPEL
            # ------------------------------------------------

            elif event in [

                "call_offer",

                "call_answer",

                "ice_candidate",

                "call_end"
            ]:

                receiver_id = data.get(
                    "to"
                )

                receiver_socket = (
                    connected_users.get(
                        receiver_id
                    )
                )

                if receiver_socket:

                    forwarded = dict(
                        data
                    )

                    forwarded[
                        "from"
                    ] = user_id

                    await receiver_socket.send_json(
                        forwarded
                    )

    except WebSocketDisconnect:

        pass

    finally:

        if (
            connected_users.get(
                user_id
            )
            == websocket
        ):

            del connected_users[
                user_id
            ]

        connection = db()

        connection.execute(
            """
            UPDATE users

            SET

            online=0,

            last_seen=?

            WHERE id=?
            """,
            (
                now(),

                user_id
            )
        )

        connection.commit()

        connection.close()


# ------------------------------------------------------------
# DÉMARRAGE
# ------------------------------------------------------------

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=PORT
)
