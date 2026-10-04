import os
import json
import uuid
import secrets
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

import asyncpg
import redis.asyncio as redis

from fastapi import (
    FastAPI,
    HTTPException,
    Depends,
    Header,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import jwt, JWTError


# ============================================================
# GENICHAT SERVER
# ============================================================

APP_NAME = "Genichat"
VERSION = "2.0.0"

DATABASE_URL = os.getenv("DATABASE_URL")
REDIS_URL = os.getenv("REDIS_URL")

JWT_SECRET = os.getenv(
    "JWT_SECRET",
    "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
)

ADMIN_USERNAME = os.getenv(
    "ADMIN_USERNAME",
    "admin"
)

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD"
)

PORT = int(os.getenv("PORT", "8000"))

JWT_ALGORITHM = "HS256"

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL manque.")

if not REDIS_URL:
    raise RuntimeError("REDIS_URL manque.")

if not ADMIN_PASSWORD:
    raise RuntimeError(
        "ADMIN_PASSWORD manque. "
        "Configure-le dans les variables d'environnement."
    )


# ============================================================
# APP
# ============================================================

app = FastAPI(
    title="Genichat Server",
    version=VERSION
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# GLOBALS
# ============================================================

db_pool = None
redis_client = None

pwd = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)

online_connections = {}


# ============================================================
# DATABASE
# ============================================================

async def init_database():

    async with db_pool.acquire() as db:

        await db.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

            public_code VARCHAR(40) UNIQUE NOT NULL,

            username VARCHAR(50) UNIQUE NOT NULL,

            password_hash TEXT NOT NULL,

            display_name VARCHAR(100),

            avatar TEXT,

            bio TEXT,

            online BOOLEAN DEFAULT FALSE,

            last_seen TIMESTAMPTZ DEFAULT NOW(),

            allow_messages BOOLEAN DEFAULT TRUE,

            allow_calls BOOLEAN DEFAULT TRUE,

            show_online BOOLEAN DEFAULT TRUE,

            show_last_seen BOOLEAN DEFAULT TRUE,

            suspended BOOLEAN DEFAULT FALSE,

            banned BOOLEAN DEFAULT FALSE,

            created_at TIMESTAMPTZ DEFAULT NOW()

        );
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS contacts (

            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

            user_id UUID NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            contact_id UUID NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            created_at TIMESTAMPTZ DEFAULT NOW(),

            UNIQUE(user_id, contact_id)

        );
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS messages (

            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

            sender_id UUID NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            receiver_id UUID NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            content TEXT,

            message_type VARCHAR(30)
                DEFAULT 'text',

            reply_to UUID,

            delivered BOOLEAN DEFAULT FALSE,

            read BOOLEAN DEFAULT FALSE,

            created_at TIMESTAMPTZ DEFAULT NOW()

        );
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS groups (

            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

            creator_id UUID NOT NULL
                REFERENCES users(id)
                ON DELETE CASCADE,

            name VARCHAR(100) NOT NULL,

            description TEXT,

            avatar TEXT,

            created_at TIMESTAMPTZ DEFAULT NOW()

        );
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS group_members (

            group_id UUID
                REFERENCES groups(id)
                ON DELETE CASCADE,

            user_id UUID
                REFERENCES users(id)
                ON DELETE CASCADE,

            role VARCHAR(20)
                DEFAULT 'member',

            read_only BOOLEAN DEFAULT FALSE,

            suspended BOOLEAN DEFAULT FALSE,

            joined_at TIMESTAMPTZ DEFAULT NOW(),

            PRIMARY KEY(group_id, user_id)

        );
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS group_messages (

            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

            group_id UUID
                REFERENCES groups(id)
                ON DELETE CASCADE,

            sender_id UUID
                REFERENCES users(id)
                ON DELETE CASCADE,

            content TEXT,

            message_type VARCHAR(30)
                DEFAULT 'text',

            created_at TIMESTAMPTZ DEFAULT NOW()

        );
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS statuses (

            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

            user_id UUID
                REFERENCES users(id)
                ON DELETE CASCADE,

            content TEXT,

            media_url TEXT,

            media_type VARCHAR(30),

            expires_at TIMESTAMPTZ NOT NULL,

            created_at TIMESTAMPTZ DEFAULT NOW()

        );
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS channels (

            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

            owner_id UUID
                REFERENCES users(id)
                ON DELETE CASCADE,

            name VARCHAR(100) UNIQUE NOT NULL,

            description TEXT,

            avatar TEXT,

            suspended BOOLEAN DEFAULT FALSE,

            created_at TIMESTAMPTZ DEFAULT NOW()

        );
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS channel_subscribers (

            channel_id UUID
                REFERENCES channels(id)
                ON DELETE CASCADE,

            user_id UUID
                REFERENCES users(id)
                ON DELETE CASCADE,

            created_at TIMESTAMPTZ DEFAULT NOW(),

            PRIMARY KEY(channel_id, user_id)

        );
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS channel_posts (

            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

            channel_id UUID
                REFERENCES channels(id)
                ON DELETE CASCADE,

            content TEXT,

            media_url TEXT,

            media_type VARCHAR(30),

            created_at TIMESTAMPTZ DEFAULT NOW()

        );
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS admin_logs (

            id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

            admin_username VARCHAR(100),

            action VARCHAR(100),

            target_id TEXT,

            details TEXT,

            created_at TIMESTAMPTZ DEFAULT NOW()

        );
        """)

        await db.execute("""
        CREATE TABLE IF NOT EXISTS server_settings (

            key VARCHAR(100) PRIMARY KEY,

            value TEXT

        );
        """)

        await db.execute("""
        INSERT INTO server_settings(key,value)

        VALUES('maintenance','false')

        ON CONFLICT(key) DO NOTHING;
        """)


# ============================================================
# PASSWORD
# ============================================================

def hash_password(password):

    return pwd.hash(password)


def check_password(password, hashed):

    return pwd.verify(password, hashed)


# ============================================================
# GENICHAT CODE
# ============================================================

async def generate_code():

    while True:

        code = (
            "GENI-"
            + secrets.token_hex(2).upper()
            + "-"
            + secrets.token_hex(2).upper()
        )

        async with db_pool.acquire() as db:

            exists = await db.fetchval(
                """
                SELECT 1
                FROM users
                WHERE public_code=$1
                """,
                code
            )

        if not exists:

            return code


# ============================================================
# JWT
# ============================================================

def create_token(user_id, role="user"):

    payload = {

        "sub": str(user_id),

        "role": role,

        "exp":
            datetime.now(timezone.utc)
            + timedelta(days=30)

    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )


def decode_token(token):

    try:

        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )

    except JWTError:

        raise HTTPException(
            status_code=401,
            detail="Session invalide."
        )


# ============================================================
# USER AUTH
# ============================================================

async def current_user(
    authorization: Optional[str] = Header(None)
):

    if not authorization:

        raise HTTPException(
            status_code=401,
            detail="Token manquant."
        )

    if not authorization.startswith("Bearer "):

        raise HTTPException(
            status_code=401,
            detail="Bearer token attendu."
        )

    token = authorization.split(" ", 1)[1]

    payload = decode_token(token)

    if payload.get("role") != "user":

        raise HTTPException(
            status_code=403,
            detail="Accès utilisateur requis."
        )

    uid = uuid.UUID(payload["sub"])

    async with db_pool.acquire() as db:

        user = await db.fetchrow(
            """
            SELECT *
            FROM users
            WHERE id=$1
            """,
            uid
        )

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Utilisateur inexistant."
        )

    if user["banned"]:

        raise HTTPException(
            status_code=403,
            detail="Compte banni."
        )

    if user["suspended"]:

        raise HTTPException(
            status_code=403,
            detail="Compte suspendu."
        )

    return user


# ============================================================
# ADMIN AUTH
# ============================================================

async def admin_required(
    authorization: Optional[str] = Header(None)
):

    if not authorization:

        raise HTTPException(
            status_code=401,
            detail="Authentification administrateur requise."
        )

    token = authorization.replace(
        "Bearer ",
        ""
    )

    payload = decode_token(token)

    if payload.get("role") != "admin":

        raise HTTPException(
            status_code=403,
            detail="Accès administrateur refusé."
        )

    return payload


# ============================================================
# MODELS
# ============================================================

class Register(BaseModel):

    username: str = Field(
        min_length=3,
        max_length=50
    )

    password: str = Field(
        min_length=6
    )

    display_name: str = Field(
        min_length=1,
        max_length=100
    )


class Login(BaseModel):

    username: str

    password: str


class ProfileUpdate(BaseModel):

    display_name: Optional[str] = None

    bio: Optional[str] = None

    avatar: Optional[str] = None


class MessageCreate(BaseModel):

    content: str

    message_type: str = "text"

    reply_to: Optional[str] = None


class GroupCreate(BaseModel):

    name: str

    description: Optional[str] = None

    avatar: Optional[str] = None

    members: list[str] = []


class GroupMessage(BaseModel):

    content: str

    message_type: str = "text"


class StatusCreate(BaseModel):

    content: Optional[str] = None

    media_url: Optional[str] = None

    media_type: Optional[str] = None


class ChannelCreate(BaseModel):

    name: str

    description: Optional[str] = None

    avatar: Optional[str] = None


class ChannelPost(BaseModel):

    content: Optional[str] = None

    media_url: Optional[str] = None

    media_type: Optional[str] = None


# ============================================================
# HEALTH
# ============================================================

@app.get("/")
async def home():

    return {
        "name": APP_NAME,
        "version": VERSION,
        "status": "online",
        "admin": "/admin"
    }


@app.get("/health")
async def health():

    postgres = False
    redis_ok = False

    try:

        async with db_pool.acquire() as db:

            await db.fetchval("SELECT 1")

        postgres = True

    except Exception:

        pass

    try:

        redis_ok = await redis_client.ping()

    except Exception:

        pass

    return {

        "server": "online",

        "postgresql": postgres,

        "redis": redis_ok,

        "time": datetime.now(
            timezone.utc
        ).isoformat()

    }


# ============================================================
# REGISTER
# ============================================================

@app.post("/api/register")
async def register(data: Register):

    code = await generate_code()

    password_hash = hash_password(
        data.password
    )

    try:

        async with db_pool.acquire() as db:

            user = await db.fetchrow(
                """
                INSERT INTO users
                (
                    public_code,
                    username,
                    password_hash,
                    display_name
                )

                VALUES($1,$2,$3,$4)

                RETURNING
                    id,
                    public_code,
                    username,
                    display_name
                """,
                code,
                data.username.lower(),
                password_hash,
                data.display_name
            )

    except asyncpg.UniqueViolationError:

        raise HTTPException(
            status_code=409,
            detail="Nom d'utilisateur déjà utilisé."
        )

    return {

        "token":
            create_token(user["id"]),

        "user": {
            "id": str(user["id"]),
            "username": user["username"],
            "display_name":
                user["display_name"],
            "public_code":
                user["public_code"]
        }

    }


# ============================================================
# LOGIN
# ============================================================

@app.post("/api/login")
async def login(data: Login):

    async with db_pool.acquire() as db:

        user = await db.fetchrow(
            """
            SELECT *
            FROM users
            WHERE username=$1
            """,
            data.username.lower()
        )

    if not user:

        raise HTTPException(
            status_code=401,
            detail="Identifiants incorrects."
        )

    if user["banned"]:

        raise HTTPException(
            status_code=403,
            detail="Compte banni."
        )

    if user["suspended"]:

        raise HTTPException(
            status_code=403,
            detail="Compte suspendu."
        )

    if not check_password(
        data.password,
        user["password_hash"]
    ):

        raise HTTPException(
            status_code=401,
            detail="Identifiants incorrects."
        )

    async with db_pool.acquire() as db:

        await db.execute(
            """
            UPDATE users

            SET online=TRUE,
                last_seen=NOW()

            WHERE id=$1
            """,
            user["id"]
        )

    await redis_client.set(
        f"presence:{user['id']}",
        "online"
    )

    return {

        "token":
            create_token(user["id"]),

        "user": {

            "id": str(user["id"]),

            "username":
                user["username"],

            "display_name":
                user["display_name"],

            "public_code":
                user["public_code"]

        }

    }


# ============================================================
# PROFILE
# ============================================================

@app.get("/api/me")
async def me(user=Depends(current_user)):

    return {

        "id": str(user["id"]),

        "username":
            user["username"],

        "public_code":
            user["public_code"],

        "display_name":
            user["display_name"],

        "avatar":
            user["avatar"],

        "bio":
            user["bio"],

        "online":
            user["online"],

        "last_seen":
            user["last_seen"]

    }


@app.patch("/api/me")
async def update_me(
    data: ProfileUpdate,
    user=Depends(current_user)
):

    async with db_pool.acquire() as db:

        await db.execute(
            """
            UPDATE users

            SET
                display_name=
                    COALESCE($1,display_name),

                bio=
                    COALESCE($2,bio),

                avatar=
                    COALESCE($3,avatar)

            WHERE id=$4
            """,
            data.display_name,
            data.bio,
            data.avatar,
            user["id"]
        )

    return {
        "message": "Profil modifié."
    }


# ============================================================
# CONTACTS
# ============================================================

@app.post("/api/contacts/{code}")
async def add_contact(
    code: str,
    user=Depends(current_user)
):

    async with db_pool.acquire() as db:

        target = await db.fetchrow(
            """
            SELECT id
            FROM users
            WHERE public_code=$1
            """,
            code.upper()
        )

        if not target:

            raise HTTPException(
                status_code=404,
                detail="Utilisateur introuvable."
            )

        if target["id"] == user["id"]:

            raise HTTPException(
                status_code=400,
                detail="Impossible de vous ajouter."
            )

        await db.execute(
            """
            INSERT INTO contacts
            (
                user_id,
                contact_id
            )

            VALUES($1,$2)

            ON CONFLICT DO NOTHING
            """,
            user["id"],
            target["id"]
        )

    return {
        "message": "Contact ajouté."
    }


@app.get("/api/contacts")
async def contacts(
    user=Depends(current_user)
):

    async with db_pool.acquire() as db:

        rows = await db.fetch(
            """
            SELECT
                u.id,
                u.public_code,
                u.username,
                u.display_name,
                u.avatar,
                u.online,
                u.last_seen

            FROM contacts c

            JOIN users u
            ON u.id=c.contact_id

            WHERE c.user_id=$1

            ORDER BY u.display_name
            """,
            user["id"]
        )

    return [
        dict(row)
        for row in rows
    ]


@app.delete("/api/contacts/{contact_id}")
async def remove_contact(
    contact_id: str,
    user=Depends(current_user)
):

    async with db_pool.acquire() as db:

        await db.execute(
            """
            DELETE FROM contacts

            WHERE user_id=$1
            AND contact_id=$2
            """,
            user["id"],
            uuid.UUID(contact_id)
        )

    return {
        "message": "Contact supprimé."
    }


# ============================================================
# MESSAGES
# ============================================================

@app.post("/api/messages/{receiver_id}")
async def send_message(
    receiver_id: str,
    data: MessageCreate,
    user=Depends(current_user)
):

    receiver = uuid.UUID(receiver_id)

    async with db_pool.acquire() as db:

        target = await db.fetchrow(
            """
            SELECT id, allow_messages
            FROM users
            WHERE id=$1
            """,
            receiver
        )

        if not target:

            raise HTTPException(
                status_code=404,
                detail="Utilisateur introuvable."
            )

        if not target["allow_messages"]:

            raise HTTPException(
                status_code=403,
                detail="Messages désactivés."
            )

        message = await db.fetchrow(
            """
            INSERT INTO messages
            (
                sender_id,
                receiver_id,
                content,
                message_type,
                reply_to
            )

            VALUES($1,$2,$3,$4,$5)

            RETURNING *
            """,
            user["id"],
            receiver,
            data.content,
            data.message_type,
            uuid.UUID(data.reply_to)
            if data.reply_to else None
        )

    payload = {

        "type": "message",

        "message": {

            "id": str(message["id"]),

            "sender_id":
                str(message["sender_id"]),

            "receiver_id":
                str(message["receiver_id"]),

            "content":
                message["content"],

            "message_type":
                message["message_type"],

            "created_at":
                message["created_at"].isoformat()

        }

    }

    await redis_client.publish(
        f"user:{receiver_id}",
        json.dumps(payload)
    )

    return payload


@app.get("/api/messages/{other_id}")
async def history(
    other_id: str,
    user=Depends(current_user)
):

    other = uuid.UUID(other_id)

    async with db_pool.acquire() as db:

        rows = await db.fetch(
            """
            SELECT *

            FROM messages

            WHERE
            (sender_id=$1 AND receiver_id=$2)

            OR

            (sender_id=$2 AND receiver_id=$1)

            ORDER BY created_at ASC
            """,
            user["id"],
            other
        )

    return [

        {
            "id": str(row["id"]),
            "sender_id":
                str(row["sender_id"]),
            "receiver_id":
                str(row["receiver_id"]),
            "content":
                row["content"],
            "message_type":
                row["message_type"],
            "delivered":
                row["delivered"],
            "read":
                row["read"],
            "created_at":
                row["created_at"].isoformat()
        }

        for row in rows
    ]


# ============================================================
# GROUPS
# ============================================================

@app.post("/api/groups")
async def create_group(
    data: GroupCreate,
    user=Depends(current_user)
):

    async with db_pool.acquire() as db:

        async with db.transaction():

            group = await db.fetchrow(
                """
                INSERT INTO groups
                (
                    creator_id,
                    name,
                    description,
                    avatar
                )

                VALUES($1,$2,$3,$4)

                RETURNING *
                """,
                user["id"],
                data.name,
                data.description,
                data.avatar
            )

            await db.execute(
                """
                INSERT INTO group_members
                (
                    group_id,
                    user_id,
                    role
                )

                VALUES($1,$2,'creator')
                """,
                group["id"],
                user["id"]
            )

            for member in data.members:

                try:

                    await db.execute(
                        """
                        INSERT INTO group_members
                        (
                            group_id,
                            user_id
                        )

                        VALUES($1,$2)

                        ON CONFLICT DO NOTHING
                        """,
                        group["id"],
                        uuid.UUID(member)
                    )

                except ValueError:

                    pass

    return {
        "id": str(group["id"]),
        "name": group["name"]
    }


@app.post("/api/groups/{group_id}/messages")
async def group_message(
    group_id: str,
    data: GroupMessage,
    user=Depends(current_user)
):

    gid = uuid.UUID(group_id)

    async with db_pool.acquire() as db:

        member = await db.fetchrow(
            """
            SELECT *
            FROM group_members
            WHERE group_id=$1
            AND user_id=$2
            """,
            gid,
            user["id"]
        )

        if not member:

            raise HTTPException(
                status_code=403,
                detail="Vous n'êtes pas membre."
            )

        if member["suspended"]:

            raise HTTPException(
                status_code=403,
                detail="Vous êtes suspendu."
            )

        if member["read_only"]:

            raise HTTPException(
                status_code=403,
                detail="Mode lecture seule."
            )

        message = await db.fetchrow(
            """
            INSERT INTO group_messages
            (
                group_id,
                sender_id,
                content,
                message_type
            )

            VALUES($1,$2,$3,$4)

            RETURNING *
            """,
            gid,
            user["id"],
            data.content,
            data.message_type
        )

        members = await db.fetch(
            """
            SELECT user_id
            FROM group_members
            WHERE group_id=$1
            """,
            gid
        )

    event = {

        "type": "group_message",

        "group_id":
            group_id,

        "message": {

            "id":
                str(message["id"]),

            "sender_id":
                str(message["sender_id"]),

            "content":
                message["content"],

            "message_type":
                message["message_type"],

            "created_at":
                message["created_at"].isoformat()

        }

    }

    for member in members:

        if member["user_id"] != user["id"]:

            await redis_client.publish(
                f"user:{member['user_id']}",
                json.dumps(event)
            )

    return event


# ============================================================
# STATUS
# ============================================================

@app.post("/api/status")
async def create_status(
    data: StatusCreate,
    user=Depends(current_user)
):

    expires = (
        datetime.now(timezone.utc)
        + timedelta(hours=24)
    )

    async with db_pool.acquire() as db:

        status = await db.fetchrow(
            """
            INSERT INTO statuses
            (
                user_id,
                content,
                media_url,
                media_type,
                expires_at
            )

            VALUES($1,$2,$3,$4,$5)

            RETURNING *
            """,
            user["id"],
            data.content,
            data.media_url,
            data.media_type,
            expires
        )

    return {
        "id": str(status["id"]),
        "expires_at":
            status["expires_at"].isoformat()
    }


@app.get("/api/status")
async def statuses(
    user=Depends(current_user)
):

    async with db_pool.acquire() as db:

        rows = await db.fetch(
            """
            SELECT
                s.*,
                u.username,
                u.display_name,
                u.avatar

            FROM statuses s

            JOIN users u
            ON u.id=s.user_id

            WHERE s.expires_at > NOW()

            AND (
                s.user_id=$1

                OR s.user_id IN
                (
                    SELECT contact_id
                    FROM contacts
                    WHERE user_id=$1
                )
            )

            ORDER BY s.created_at DESC
            """,
            user["id"]
        )

    return [
        {
            "id": str(row["id"]),
            "user_id": str(row["user_id"]),
            "username": row["username"],
            "display_name":
                row["display_name"],
            "avatar": row["avatar"],
            "content":
                row["content"],
            "media_url":
                row["media_url"],
            "media_type":
                row["media_type"],
            "expires_at":
                row["expires_at"].isoformat()
        }
        for row in rows
    ]


# ============================================================
# CHANNELS
# ============================================================

@app.post("/api/channels")
async def create_channel(
    data: ChannelCreate,
    user=Depends(current_user)
):

    async with db_pool.acquire() as db:

        try:

            channel = await db.fetchrow(
                """
                INSERT INTO channels
                (
                    owner_id,
                    name,
                    description,
                    avatar
                )

                VALUES($1,$2,$3,$4)

                RETURNING *
                """,
                user["id"],
                data.name,
                data.description,
                data.avatar
            )

        except asyncpg.UniqueViolationError:

            raise HTTPException(
                status_code=409,
                detail="Cette chaîne existe déjà."
            )

    return {
        "id": str(channel["id"]),
        "name": channel["name"]
    }


@app.post("/api/channels/{channel_id}/subscribe")
async def subscribe(
    channel_id: str,
    user=Depends(current_user)
):

    async with db_pool.acquire() as db:

        await db.execute(
            """
            INSERT INTO channel_subscribers
            (
                channel_id,
                user_id
            )

            VALUES($1,$2)

            ON CONFLICT DO NOTHING
            """,
            uuid.UUID(channel_id),
            user["id"]
        )

    return {
        "message": "Abonnement effectué."
    }


@app.post("/api/channels/{channel_id}/posts")
async def channel_post(
    channel_id: str,
    data: ChannelPost,
    user=Depends(current_user)
):

    cid = uuid.UUID(channel_id)

    async with db_pool.acquire() as db:

        channel = await db.fetchrow(
            """
            SELECT *
            FROM channels
            WHERE id=$1
            """,
            cid
        )

        if not channel:

            raise HTTPException(
                status_code=404,
                detail="Chaîne introuvable."
            )

        if channel["owner_id"] != user["id"]:

            raise HTTPException(
                status_code=403,
                detail="Propriétaire uniquement."
            )

        post = await db.fetchrow(
            """
            INSERT INTO channel_posts
            (
                channel_id,
                content,
                media_url,
                media_type
            )

            VALUES($1,$2,$3,$4)

            RETURNING *
            """,
            cid,
            data.content,
            data.media_url,
            data.media_type
        )

        subscribers = await db.fetch(
            """
            SELECT user_id
            FROM channel_subscribers
            WHERE channel_id=$1
            """,
            cid
        )

    event = {

        "type": "channel_post",

        "channel_id":
            channel_id,

        "post": {

            "id":
                str(post["id"]),

            "content":
                post["content"],

            "media_url":
                post["media_url"],

            "media_type":
                post["media_type"]

        }

    }

    for subscriber in subscribers:

        await redis_client.publish(
            f"user:{subscriber['user_id']}",
            json.dumps(event)
        )

    return event


# ============================================================
# WEBRTC / REALTIME WEBSOCKET
# ============================================================

@app.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket
):

    token = websocket.query_params.get("token")

    if not token:

        await websocket.close(
            code=1008
        )

        return

    try:

        payload = decode_token(token)

        if payload.get("role") != "user":

            raise Exception()

        user_id = payload["sub"]

    except Exception:

        await websocket.close(
            code=1008
        )

        return

    await websocket.accept()

    user_channel = redis_client.pubsub()

    await user_channel.subscribe(
        f"user:{user_id}"
    )

    online_connections[user_id] = websocket

    await redis_client.set(
        f"presence:{user_id}",
        "online"
    )

    async with db_pool.acquire() as db:

        await db.execute(
            """
            UPDATE users

            SET online=TRUE,
                last_seen=NOW()

            WHERE id=$1
            """,
            uuid.UUID(user_id)
        )

    try:

        while True:

            message = await user_channel.get_message(
                ignore_subscribe_messages=True,
                timeout=0.2
            )

            if message:

                await websocket.send_text(
                    message["data"]
                )

            try:

                incoming = await websocket.receive_text()

                data = json.loads(incoming)

                # ------------------------------------------------
                # WEBRTC SIGNALISATION
                # ------------------------------------------------

                if data.get("type") in [
                    "call_offer",
                    "call_answer",
                    "ice_candidate",
                    "call_reject",
                    "call_end"
                ]:

                    target = data.get(
                        "target_user_id"
                    )

                    if target:

                        data["sender_user_id"] = user_id

                        await redis_client.publish(
                            f"user:{target}",
                            json.dumps(data)
                        )

            except Exception:

                pass

    except WebSocketDisconnect:

        pass

    finally:

        online_connections.pop(
            user_id,
            None
        )

        await user_channel.unsubscribe(
            f"user:{user_id}"
        )

        await user_channel.close()

        await redis_client.delete(
            f"presence:{user_id}"
        )

        async with db_pool.acquire() as db:

            await db.execute(
                """
                UPDATE users

                SET online=FALSE,
                    last_seen=NOW()

                WHERE id=$1
                """,
                uuid.UUID(user_id)
            )


# ============================================================
# ADMIN LOG
# ============================================================

async def admin_log(
    admin,
    action,
    target="",
    details=""
):

    async with db_pool.acquire() as db:

        await db.execute(
            """
            INSERT INTO admin_logs
            (
                admin_username,
                action,
                target_id,
                details
            )

            VALUES($1,$2,$3,$4)
            """,
            admin.get("sub", "admin"),
            action,
            target,
            details
        )


# ============================================================
# ADMIN LOGIN
# ============================================================

class AdminLogin(BaseModel):

    username: str

    password: str


@app.post("/admin/api/login")
async def admin_login(data: AdminLogin):

    if data.username != ADMIN_USERNAME:

        raise HTTPException(
            status_code=401,
            detail="Identifiants incorrects."
        )

    if not secrets.compare_digest(
        data.password,
        ADMIN_PASSWORD
    ):

        raise HTTPException(
            status_code=401,
            detail="Identifiants incorrects."
        )

    token = create_token(
        "ADMIN",
        "admin"
    )

    return {
        "token": token
    }


# ============================================================
# ADMIN DASHBOARD DATA
# ============================================================

@app.get("/admin/api/dashboard")
async def admin_dashboard(
    admin=Depends(admin_required)
):

    async with db_pool.acquire() as db:

        users = await db.fetchval(
            "SELECT COUNT(*) FROM users"
        )

        online = await db.fetchval(
            """
            SELECT COUNT(*)
            FROM users
            WHERE online=TRUE
            """
        )

        groups = await db.fetchval(
            "SELECT COUNT(*) FROM groups"
        )

        channels = await db.fetchval(
            "SELECT COUNT(*) FROM channels"
        )

        messages = await db.fetchval(
            "SELECT COUNT(*) FROM messages"
        )

        posts = await db.fetchval(
            "SELECT COUNT(*) FROM channel_posts"
        )

        recent_users = await db.fetch(
            """
            SELECT
                id,
                username,
                display_name,
                public_code,
                online,
                suspended,
                banned,
                created_at

            FROM users

            ORDER BY created_at DESC

            LIMIT 20
            """
        )

    redis_ok = False

    try:

        redis_ok = await redis_client.ping()

    except Exception:

        pass

    return {

        "server": {

            "name": APP_NAME,

            "version": VERSION,

            "status": "online",

            "time":
                datetime.now(
                    timezone.utc
                ).isoformat()

        },

        "statistics": {

            "users": users,

            "online": online,

            "groups": groups,

            "channels": channels,

            "messages": messages,

            "channel_posts": posts,

            "websocket_connections":
                len(online_connections)

        },

        "services": {

            "postgresql": True,

            "redis": redis_ok

        },

        "users": [

            {

                "id": str(row["id"]),

                "username":
                    row["username"],

                "display_name":
                    row["display_name"],

                "public_code":
                    row["public_code"],

                "online":
                    row["online"],

                "suspended":
                    row["suspended"],

                "banned":
                    row["banned"],

                "created_at":
                    row["created_at"].isoformat()

            }

            for row in recent_users
        ]

    }


# ============================================================
# ADMIN USER SEARCH
# ============================================================

@app.get("/admin/api/users")
async def admin_users(
    q: str = "",
    admin=Depends(admin_required)
):

    async with db_pool.acquire() as db:

        if q:

            rows = await db.fetch(
                """
                SELECT
                    id,
                    username,
                    display_name,
                    public_code,
                    online,
                    suspended,
                    banned,
                    created_at

                FROM users

                WHERE
                    username ILIKE $1
                    OR display_name ILIKE $1
                    OR public_code ILIKE $1

                ORDER BY created_at DESC

                LIMIT 100
                """,
                f"%{q}%"
            )

        else:

            rows = await db.fetch(
                """
                SELECT
                    id,
                    username,
                    display_name,
                    public_code,
                    online,
                    suspended,
                    banned,
                    created_at

                FROM users

                ORDER BY created_at DESC

                LIMIT 100
                """
            )

    return [

        {

            "id": str(row["id"]),

            "username":
                row["username"],

            "display_name":
                row["display_name"],

            "public_code":
                row["public_code"],

            "online":
                row["online"],

            "suspended":
                row["suspended"],

            "banned":
                row["banned"]

        }

        for row in rows
    ]


# ============================================================
# ADMIN ACTIONS
# ============================================================

@app.post("/admin/api/users/{user_id}/suspend")
async def suspend_user(
    user_id: str,
    admin=Depends(admin_required)
):

    uid = uuid.UUID(user_id)

    async with db_pool.acquire() as db:

        await db.execute(
            """
            UPDATE users
            SET suspended=TRUE
            WHERE id=$1
            """,
            uid
        )

    await admin_log(
        admin,
        "SUSPEND_USER",
        user_id
    )

    return {
        "message": "Utilisateur suspendu."
    }


@app.post("/admin/api/users/{user_id}/unsuspend")
async def unsuspend_user(
    user_id: str,
    admin=Depends(admin_required)
):

    uid = uuid.UUID(user_id)

    async with db_pool.acquire() as db:

        await db.execute(
            """
            UPDATE users
            SET suspended=FALSE
            WHERE id=$1
            """,
            uid
        )

    await admin_log(
        admin,
        "UNSUSPEND_USER",
        user_id
    )

    return {
        "message": "Suspension retirée."
    }


@app.post("/admin/api/users/{user_id}/ban")
async def ban_user(
    user_id: str,
    admin=Depends(admin_required)
):

    uid = uuid.UUID(user_id)

    async with db_pool.acquire() as db:

        await db.execute(
            """
            UPDATE users

            SET banned=TRUE,
                online=FALSE

            WHERE id=$1
            """,
            uid
        )

    await redis_client.publish(
        f"user:{user_id}",
        json.dumps({
            "type": "force_logout",
            "reason": "Compte banni."
        })
    )

    await admin_log(
        admin,
        "BAN_USER",
        user_id
    )

    return {
        "message": "Utilisateur banni."
    }


@app.post("/admin/api/users/{user_id}/unban")
async def unban_user(
    user_id: str,
    admin=Depends(admin_required)
):

    uid = uuid.UUID(user_id)

    async with db_pool.acquire() as db:

        await db.execute(
            """
            UPDATE users
            SET banned=FALSE
            WHERE id=$1
            """,
            uid
        )

    await admin_log(
        admin,
        "UNBAN_USER",
        user_id
    )

    return {
        "message": "Utilisateur débanni."
    }


@app.post("/admin/api/users/{user_id}/logout")
async def force_logout(
    user_id: str,
    admin=Depends(admin_required)
):

    await redis_client.publish(
        f"user:{user_id}",
        json.dumps({
            "type": "force_logout"
        })
    )

    await admin_log(
        admin,
        "FORCE_LOGOUT",
        user_id
    )

    return {
        "message": "Déconnexion demandée."
    }


# ============================================================
# ADMIN MAINTENANCE
# ============================================================

@app.post("/admin/api/maintenance/{state}")
async def maintenance(
    state: str,
    admin=Depends(admin_required)
):

    if state not in ["on", "off"]:

        raise HTTPException(
            status_code=400,
            detail="État invalide."
        )

    value = "true" if state == "on" else "false"

    async with db_pool.acquire() as db:

        await db.execute(
            """
            INSERT INTO server_settings
            (
                key,
                value
            )

            VALUES('maintenance',$1)

            ON CONFLICT(key)

            DO UPDATE SET value=$1
            """,
            value
        )

    await admin_log(
        admin,
        "MAINTENANCE",
        details=state
    )

    return {
        "maintenance": value
    }


# ============================================================
# ADMIN LOGS
# ============================================================

@app.get("/admin/api/logs")
async def logs(
    admin=Depends(admin_required)
):

    async with db_pool.acquire() as db:

        rows = await db.fetch(
            """
            SELECT *

            FROM admin_logs

            ORDER BY created_at DESC

            LIMIT 100
            """
        )

    return [

        {

            "admin":
                row["admin_username"],

            "action":
                row["action"],

            "target":
                row["target_id"],

            "details":
                row["details"],

            "created_at":
                row["created_at"].isoformat()

        }

        for row in rows
    ]


# ============================================================
# ADMIN HTML
# ============================================================

ADMIN_HTML = r"""
<!DOCTYPE html>

<html lang="fr">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>Genichat Control Center</title>

<script src="https://cdn.jsdelivr.net/npm/three@0.160.0/build/three.min.js"></script>

<style>

* {
    box-sizing: border-box;
}

body {

    margin: 0;

    background:
        radial-gradient(
            circle at top right,
            #172554,
            #050816 45%,
            #02030a
        );

    color: #f5f7ff;

    font-family:
        Inter,
        system-ui,
        sans-serif;

    min-height: 100vh;
}

header {

    height: 70px;

    display: flex;

    align-items: center;

    justify-content: space-between;

    padding: 0 22px;

    border-bottom:
        1px solid rgba(255,255,255,.08);

    background:
        rgba(3,7,18,.82);

    backdrop-filter: blur(18px);

    position: sticky;

    top: 0;

    z-index: 10;
}

.logo {

    font-size: 21px;

    font-weight: 800;
}

.logo span {

    color: #6ee7ff;
}

.status {

    display: flex;

    gap: 8px;

    align-items: center;

    font-size: 13px;

    color: #9ca3af;
}

.dot {

    width: 9px;

    height: 9px;

    border-radius: 50%;

    background: #22c55e;

    box-shadow:
        0 0 15px #22c55e;
}

.layout {

    display: grid;

    grid-template-columns:
        230px 1fr;

    min-height:
        calc(100vh - 70px);
}

nav {

    border-right:
        1px solid rgba(255,255,255,.07);

    padding: 20px 12px;

    background:
        rgba(2,6,23,.62);
}

nav button {

    width: 100%;

    text-align: left;

    padding: 12px 14px;

    margin-bottom: 7px;

    border: 0;

    border-radius: 12px;

    background: transparent;

    color: #aeb7c9;

    cursor: pointer;

    font-size: 14px;
}

nav button:hover,
nav button.active {

    background:
        rgba(110,231,255,.12);

    color: #fff;
}

main {

    padding: 22px;

    overflow: auto;
}

.page {

    display: none;
}

.page.active {

    display: block;
}

.cards {

    display: grid;

    grid-template-columns:
        repeat(auto-fit,minmax(160px,1fr));

    gap: 14px;
}

.card {

    background:
        rgba(15,23,42,.72);

    border:
        1px solid rgba(255,255,255,.07);

    border-radius: 18px;

    padding: 18px;

    box-shadow:
        0 15px 40px rgba(0,0,0,.2);
}

.card small {

    color: #8791a5;
}

.number {

    margin-top: 8px;

    font-size: 30px;

    font-weight: 800;
}

.panel {

    background:
        rgba(15,23,42,.68);

    border:
        1px solid rgba(255,255,255,.07);

    border-radius: 18px;

    padding: 18px;

    margin-top: 16px;
}

.panel h2 {

    margin-top: 0;

    font-size: 18px;
}

.grid2 {

    display: grid;

    grid-template-columns:
        1.5fr 1fr;

    gap: 16px;

    margin-top: 16px;
}

#network {

    height: 430px;

    border-radius: 16px;

    overflow: hidden;

    background: #020617;
}

table {

    width: 100%;

    border-collapse: collapse;
}

th,
td {

    padding: 11px;

    border-bottom:
        1px solid rgba(255,255,255,.06);

    text-align: left;

    font-size: 13px;
}

th {

    color: #8d98aa;
}

button.action {

    border: 0;

    padding: 7px 10px;

    border-radius: 9px;

    background:
        rgba(255,255,255,.08);

    color: white;

    cursor: pointer;

    margin: 2px;
}

button.danger {

    background:
        rgba(239,68,68,.18);

    color: #fca5a5;
}

input {

    background:
        rgba(255,255,255,.06);

    color: white;

    border:
        1px solid rgba(255,255,255,.1);

    border-radius: 10px;

    padding: 10px;

    outline: none;
}

.login {

    min-height: 100vh;

    display: flex;

    align-items: center;

    justify-content: center;

    padding: 20px;
}

.login-box {

    width: min(420px,100%);

    background:
        rgba(15,23,42,.85);

    border:
        1px solid rgba(255,255,255,.08);

    padding: 30px;

    border-radius: 24px;

    box-shadow:
        0 30px 100px rgba(0,0,0,.5);
}

.login-box input {

    width: 100%;

    margin:
        7px 0;
}

.primary {

    width: 100%;

    margin-top: 12px;

    padding: 12px;

    border: 0;

    border-radius: 11px;

    background:
        linear-gradient(
            135deg,
            #06b6d4,
            #6366f1
        );

    color: white;

    font-weight: 700;

    cursor: pointer;
}

.alert {

    color: #fca5a5;

    font-size: 13px;

    margin-top: 10px;
}

@media(max-width:800px) {

    .layout {

        grid-template-columns: 1fr;

    }

    nav {

        display: flex;

        overflow-x: auto;

        border-right: 0;

        border-bottom:
            1px solid rgba(255,255,255,.07);
    }

    nav button {

        min-width: max-content;

    }

    .grid2 {

        grid-template-columns: 1fr;

    }

}

</style>

</head>

<body>

<div id="login" class="login">

    <div class="login-box">

        <h1>Genichat Control</h1>

        <p>
            Console d'administration sécurisée
        </p>

        <input
            id="adminUser"
            placeholder="Nom administrateur"
        >

        <input
            id="adminPass"
            type="password"
            placeholder="Mot de passe"
        >

        <button
            class="primary"
            onclick="loginAdmin()"
        >
            Entrer dans le centre de contrôle
        </button>

        <div
            id="loginError"
            class="alert"
        ></div>

    </div>

</div>


<div id="app" style="display:none">

<header>

    <div class="logo">
        GENI<span>CHAT</span>
        <small> CONTROL</small>
    </div>

    <div class="status">
        <span class="dot"></span>
        Serveur opérationnel
    </div>

</header>


<div class="layout">

<nav>

    <button
        class="active"
        onclick="page('dashboard',this)"
    >
        📊 Dashboard
    </button>

    <button
        onclick="page('users',this)"
    >
        👤 Utilisateurs
    </button>

    <button
        onclick="page('network',this)"
    >
        🌐 Réseau 3D
    </button>

    <button
        onclick="page('security',this)"
    >
        🛡️ Sécurité
    </button>

    <button
        onclick="page('logs',this)"
    >
        📜 Journal
    </button>

</nav>


<main>

<!-- DASHBOARD -->

<section
id="dashboard"
class="page active"
>

<h1>Centre de contrôle</h1>

<div class="cards">

<div class="card">
<small>Utilisateurs</small>
<div id="usersCount" class="number">0</div>
</div>

<div class="card">
<small>En ligne</small>
<div id="onlineCount" class="number">0</div>
</div>

<div class="card">
<small>Groupes</small>
<div id="groupsCount" class="number">0</div>
</div>

<div class="card">
<small>Chaînes</small>
<div id="channelsCount" class="number">0</div>
</div>

<div class="card">
<small>Messages</small>
<div id="messagesCount" class="number">0</div>
</div>

<div class="card">
<small>WebSockets</small>
<div id="wsCount" class="number">0</div>
</div>

</div>


<div class="grid2">

<div class="panel">

<h2>🌐 Architecture Genichat</h2>

<div id="network"></div>

</div>


<div class="panel">

<h2>⚙️ Services</h2>

<p>
PostgreSQL :
<strong id="postgres">
...
</strong>
</p>

<p>
Redis :
<strong id="redis">
...
</strong>
</p>

<p>
Serveur :
<strong>ONLINE</strong>
</p>

<p>
Version :
<strong id="version">
...
</strong>
</p>

</div>

</div>

</section>


<!-- USERS -->

<section
id="users"
class="page"
>

<h1>👤 Utilisateurs</h1>

<div class="panel">

<input
id="search"
placeholder="Rechercher username, nom ou code..."
oninput="searchUsers()"
>

<div style="overflow:auto;margin-top:15px">

<table>

<thead>

<tr>

<th>Utilisateur</th>
<th>Code</th>
<th>État</th>
<th>Actions</th>

</tr>

</thead>

<tbody id="usersTable"></tbody>

</table>

</div>

</div>

</section>


<!-- NETWORK -->

<section
id="networkPage"
class="page"
>

<h1>🌐 Réseau 3D</h1>

<div class="panel">

<div id="networkLarge"
style="height:600px"
></div>

</div>

</section>


<!-- SECURITY -->

<section
id="security"
class="page"
>

<h1>🛡️ Sécurité</h1>

<div class="panel">

<h2>Mode maintenance</h2>

<button
class="action"
onclick="maintenance('on')"
>
Activer
</button>

<button
class="action"
onclick="maintenance('off')"
>
Désactiver
</button>

</div>

<div class="panel">

<h2>Contrôle système</h2>

<p>
Les actions critiques sont enregistrées
dans le journal administrateur.
</p>

</div>

</section>


<!-- LOGS -->

<section
id="logs"
class="page"
>

<h1>📜 Journal administrateur</h1>

<div class="panel">

<table>

<thead>

<tr>
<th>Admin</th>
<th>Action</th>
<th>Cible</th>
<th>Date</th>
</tr>

</thead>

<tbody id="logsTable"></tbody>

</table>

</div>

</section>

</main>

</div>

</div>


<script>

let token = localStorage.getItem(
    "genichat_admin_token"
);


function headers() {

    return {

        "Content-Type":
            "application/json",

        "Authorization":
            "Bearer " + token

    };

}


async function loginAdmin() {

    const username =
        document.getElementById(
            "adminUser"
        ).value;

    const password =
        document.getElementById(
            "adminPass"
        ).value;

    const response =
        await fetch(
            "/admin/api/login",
            {

                method: "POST",

                headers: {
                    "Content-Type":
                        "application/json"
                },

                body: JSON.stringify({

                    username,

                    password

                })

            }
        );

    if (!response.ok) {

        document.getElementById(
            "loginError"
        ).textContent =
            "Identifiants incorrects.";

        return;

    }

    const data =
        await response.json();

    token = data.token;

    localStorage.setItem(
        "genichat_admin_token",
        token
    );

    showApp();

}


function showApp() {

    document.getElementById(
        "login"
    ).style.display = "none";

    document.getElementById(
        "app"
    ).style.display = "block";

    create3D(
        "network"
    );

    create3D(
        "networkLarge"
    );

    refresh();

}


async function refresh() {

    if (!token) return;

    const response =
        await fetch(
            "/admin/api/dashboard",
            {
                headers: headers()
            }
        );

    if (response.status === 401) {

        localStorage.removeItem(
            "genichat_admin_token"
        );

        location.reload();

        return;

    }

    const data =
        await response.json();


    document.getElementById(
        "usersCount"
    ).textContent =
        data.statistics.users;

    document.getElementById(
        "onlineCount"
    ).textContent =
        data.statistics.online;

    document.getElementById(
        "groupsCount"
    ).textContent =
        data.statistics.groups;

    document.getElementById(
        "channelsCount"
    ).textContent =
        data.statistics.channels;

    document.getElementById(
        "messagesCount"
    ).textContent =
        data.statistics.messages;

    document.getElementById(
        "wsCount"
    ).textContent =
        data.statistics.websocket_connections;

    document.getElementById(
        "postgres"
    ).textContent =
        data.services.postgresql
        ? "ONLINE"
        : "OFFLINE";

    document.getElementById(
        "redis"
    ).textContent =
        data.services.redis
        ? "ONLINE"
        : "OFFLINE";

    document.getElementById(
        "version"
    ).textContent =
        data.server.version;

    renderUsers(
        data.users
    );

}


function renderUsers(users) {

    const table =
        document.getElementById(
            "usersTable"
        );

    table.innerHTML = "";

    users.forEach(user => {

        const tr =
            document.createElement("tr");

        const state =
            user.banned
            ? "🚫 Banni"
            : user.suspended
            ? "⏸ Suspendu"
            : user.online
            ? "🟢 En ligne"
            : "⚪ Hors ligne";

        tr.innerHTML = `

<td>

<strong>
${escapeHtml(user.display_name || "")}
</strong>

<br>

<small>
@${escapeHtml(user.username)}
</small>

</td>

<td>
${escapeHtml(user.public_code)}
</td>

<td>
${state}
</td>

<td>

<button
class="action"
onclick="suspendUser('${user.id}')"
>
Suspendre
</button>

<button
class="action danger"
onclick="banUser('${user.id}')"
>
Bannir
</button>

<button
class="action"
onclick="logoutUser('${user.id}')"
>
Déconnecter
</button>

</td>

`;

        table.appendChild(tr);

    });

}


async function searchUsers() {

    const q =
        document.getElementById(
            "search"
        ).value;

    const response =
        await fetch(
            "/admin/api/users?q="
            + encodeURIComponent(q),
            {
                headers: headers()
            }
        );

    const users =
        await response.json();

    renderUsers(users);

}


async function suspendUser(id) {

    if (!confirm(
        "Suspendre cet utilisateur ?"
    )) return;

    await fetch(
        "/admin/api/users/"
        + id
        + "/suspend",
        {
            method: "POST",
            headers: headers()
        }
    );

    refresh();

}


async function banUser(id) {

    if (!confirm(
        "Bannir définitivement cet utilisateur ?"
    )) return;

    await fetch(
        "/admin/api/users/"
        + id
        + "/ban",
        {
            method: "POST",
            headers: headers()
        }
    );

    refresh();

}


async function logoutUser(id) {

    await fetch(
        "/admin/api/users/"
        + id
        + "/logout",
        {
            method: "POST",
            headers: headers()
        }
    );

}


async function maintenance(state) {

    if (!confirm(
        "Modifier le mode maintenance ?"
    )) return;

    await fetch(
        "/admin/api/maintenance/"
        + state,
        {
            method: "POST",
            headers: headers()
        }
    );

    alert(
        "Mode maintenance : "
        + state
    );

}


async function loadLogs() {

    const response =
        await fetch(
            "/admin/api/logs",
            {
                headers: headers()
            }
        );

    const logs =
        await response.json();

    const table =
        document.getElementById(
            "logsTable"
        );

    table.innerHTML = "";

    logs.forEach(log => {

        const tr =
            document.createElement("tr");

        tr.innerHTML = `

<td>${escapeHtml(log.admin)}</td>

<td>${escapeHtml(log.action)}</td>

<td>${escapeHtml(log.target || "")}</td>

<td>${escapeHtml(log.created_at)}</td>

`;

        table.appendChild(tr);

    });

}


function page(name, button) {

    document
        .querySelectorAll(".page")
        .forEach(p => {
            p.classList.remove("active");
        });

    document
        .querySelectorAll("nav button")
        .forEach(b => {
            b.classList.remove("active");
        });

    if (name === "network") {

        document
            .getElementById("networkPage")
            .classList.add("active");

    } else {

        document
            .getElementById(name)
            .classList.add("active");

    }

    button.classList.add("active");

    if (name === "logs") {

        loadLogs();

    }

}


function escapeHtml(value) {

    return String(value)
        .replaceAll("&","&amp;")
        .replaceAll("<","&lt;")
        .replaceAll(">","&gt;")
        .replaceAll('"',"&quot;")
        .replaceAll("'","&#039;");

}


/* ========================================================
   3D NETWORK
======================================================== */

function create3D(elementId) {

    const container =
        document.getElementById(
            elementId
        );

    if (!container) return;

    const scene =
        new THREE.Scene();

    scene.background =
        new THREE.Color(
            0x020617
        );

    const camera =
        new THREE.PerspectiveCamera(
            60,
            container.clientWidth /
            container.clientHeight,
            0.1,
            1000
        );

    camera.position.z = 12;

    const renderer =
        new THREE.WebGLRenderer({
            antialias: true
        });

    renderer.setSize(
        container.clientWidth,
        container.clientHeight
    );

    container.appendChild(
        renderer.domElement
    );


    const nodes = [];

    const positions = [

        [0,0,0],

        [-4,2,-1],

        [4,2,-1],

        [-4,-2,-1],

        [4,-2,-1],

        [0,-4,-2],

        [0,4,-2]

    ];


    positions.forEach(
        (position,index) => {

            const geometry =
                new THREE.SphereGeometry(
                    index === 0
                    ? 0.65
                    : 0.38,
                    24,
                    24
                );

            const material =
                new THREE.MeshBasicMaterial({
                    color:
                        index === 0
                        ? 0x22d3ee
                        : 0x6366f1
                });

            const mesh =
                new THREE.Mesh(
                    geometry,
                    material
                );

            mesh.position.set(
                position[0],
                position[1],
                position[2]
            );

            scene.add(mesh);

            nodes.push(mesh);

        }
    );


    for (
        let i = 1;
        i < nodes.length;
        i++
    ) {

        const points = [

            nodes[0].position,
            nodes[i].position

        ];

        const geometry =
            new THREE.BufferGeometry()
                .setFromPoints(points);

        const material =
            new THREE.LineBasicMaterial({
                color: 0x334155
            });

        const line =
            new THREE.Line(
                geometry,
                material
            );

        scene.add(line);

    }


    function animate() {

        requestAnimationFrame(
            animate
        );

        nodes.forEach(
            (node,index) => {

                node.rotation.y +=
                    0.005;

                if (index !== 0) {

                    node.position.y +=
                        Math.sin(
                            Date.now()*0.001
                            + index
                        ) * 0.0005;

                }

            }
        );

        scene.rotation.y +=
            0.0015;

        renderer.render(
            scene,
            camera
        );

    }

    animate();

}


if (token) {

    showApp();

}

setInterval(
    refresh,
    5000
);

</script>

</body>

</html>
"""


# ============================================================
# ADMIN PAGE
# ============================================================

@app.get(
    "/admin",
    response_class=HTMLResponse
)
async def admin_page():

    return ADMIN_HTML


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():

    global db_pool
    global redis_client

    db_pool = await asyncpg.create_pool(
        DATABASE_URL,
        min_size=2,
        max_size=30
    )

    redis_client = redis.from_url(
        REDIS_URL,
        decode_responses=True
    )

    await init_database()


@app.on_event("shutdown")
async def shutdown():

    global db_pool
    global redis_client

    if db_pool:

        await db_pool.close()

    if redis_client:

        await redis_client.close()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    import uvicorn

    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=PORT,
        reload=False
    )
