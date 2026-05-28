# main.py
from fastapi import FastAPI, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta, time, timezone
from math import radians, sin, cos, sqrt, atan2
import sqlite3, hashlib, jwt, os

app = FastAPI()
SECRET = "change-this-secret-in-production"
ALGORITHM = "HS256"
DB = "presence.db"
MAX_SESSION_HOURS = int(os.getenv("MAX_SESSION_HOURS", "16"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_FILE = os.path.join(BASE_DIR, "static", "index.html")
bearer = HTTPBearer()

# ── DB SETUP ──────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn

def utc_now():
    return datetime.now(timezone.utc)

def utc_now_iso():
    return utc_now().isoformat()

def parse_utc(value: str):
    return datetime.fromisoformat(value)

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS presence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            verify_in_time TEXT NOT NULL,
            verify_out_time TEXT,
            latitude REAL,
            longitude REAL,
            closed_reason TEXT,
            auto_closed INTEGER NOT NULL DEFAULT 0,
            
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS location_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            radius_meters REAL NOT NULL
        );
    """)

    cols = [r["name"] for r in db.execute("PRAGMA table_info(presence)").fetchall()]

    if "verify_in_time" not in cols and "checkin_time" in cols:
        db.execute(
            "ALTER TABLE presence RENAME COLUMN checkin_time TO verify_in_time"
        )

    if "closed_reason" not in cols:
        db.execute(
            "ALTER TABLE presence ADD COLUMN closed_reason TEXT"
        )

    if "auto_closed" not in cols:
        db.execute(
            "ALTER TABLE presence ADD COLUMN auto_closed INTEGER NOT NULL DEFAULT 0"
        )

    db.execute("""
        CREATE UNIQUE INDEX IF NOT EXISTS idx_presence_one_open_session
        ON presence(user_id)
        WHERE verify_out_time IS NULL
    """)

    db.commit()
    db.close()

init_db()

# ── HELPERS ───────────────────────────────────────────────
def hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode()).hexdigest()

def make_token(user_id: int, role: str) -> str:
    payload = {"sub": str(user_id), "role": role, "exp": datetime.utcnow() + timedelta(hours=24)}
    return jwt.encode(payload, SECRET, algorithm=ALGORITHM)

def decode_token(credentials: HTTPAuthorizationCredentials = Depends(bearer)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET, algorithms=[ALGORITHM])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

# ── SCHEMAS ───────────────────────────────────────────────
class AuthBody(BaseModel):
    username: str
    password: str
    role: str = "user"  # used only for signup

class VerifyinBody(BaseModel):
    latitude: float
    longitude: float

class LocationSettingsBody(BaseModel):
    start_time: str
    end_time: str
    latitude: float
    longitude: float
    radius_meters: float

def distance_meters(lat1, lon1, lat2, lon2):
    R = 6371000
    dlat = radians(lat2 - lat1)
    dlon = radians(lon2 - lon1)
    a = (
        sin(dlat / 2) ** 2
        + cos(radians(lat1)) * cos(radians(lat2)) * sin(dlon / 2) ** 2
    )
    return 2 * R * atan2(sqrt(a), sqrt(1 - a))

def auto_close_abandoned_sessions(db):
    cutoff = utc_now() - timedelta(hours=MAX_SESSION_HOURS)

    stale_rows = db.execute("""
        SELECT id, verify_in_time
        FROM presence
        WHERE verify_out_time IS NULL
    """).fetchall()

    for row in stale_rows:
        checkin = parse_utc(row["verify_in_time"])

        if checkin <= cutoff:
            checkout_time = checkin + timedelta(hours=MAX_SESSION_HOURS)

            db.execute("""
                UPDATE presence
                SET verify_out_time=?,
                    closed_reason=?,
                    auto_closed=1
                WHERE id=?
                AND verify_out_time IS NULL
            """, (
                checkout_time.isoformat(),
                "MAX_DURATION_EXCEEDED",
                row["id"]
            ))
# ── AUTH ROUTES ───────────────────────────────────────────
@app.post("/api/signup")
def signup(body: AuthBody):
    db = get_db()
    try:
        if body.role not in ["user", "organization"]:
            raise HTTPException(400, "Invalid role")
        db.execute("INSERT INTO users (username, password, role) VALUES (?,?,?)",
            (body.username, hash_pw(body.password), body.role))
        db.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, "Username taken")
    finally:
        db.close()
    return {"message": "Account created"}

@app.post("/api/login")
def login(body: AuthBody):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username=? AND password=?",
                      (body.username, hash_pw(body.password))).fetchone()
    db.close()
    if not user:
        raise HTTPException(401, "Bad credentials")
    return {"token": make_token(user["id"], user["role"]), "role": user["role"], "username": user["username"]}

# ── USER ROUTES ───────────────────────────────────────
@app.post("/api/verifyin")
def verifyin(body: VerifyinBody, token=Depends(decode_token)):
    if token["role"] != "user":
        raise HTTPException(403, "Users only")

    db = get_db()
    user_id = int(token["sub"])

    try:
        db.execute("BEGIN IMMEDIATE")

        auto_close_abandoned_sessions(db)

        active = db.execute("""
            SELECT *
            FROM presence
            WHERE user_id=?
            AND verify_out_time IS NULL
            LIMIT 1
        """, (user_id,)).fetchone()

        if active:
            db.commit()
            return {
                "message": "Already checked in",
                "session": dict(active),
                "state": "IN"
            }

        settings = db.execute(
            "SELECT * FROM location_settings WHERE id=1"
        ).fetchone()

        if settings:
            dist = distance_meters(
                body.latitude,
                body.longitude,
                settings["latitude"],
                settings["longitude"],
            )

            if dist > settings["radius_meters"]:
                db.rollback()
                raise HTTPException(400, "Outside allowed location")

        cursor = db.execute("""
            INSERT INTO presence (
                user_id,
                verify_in_time,
                latitude,
                longitude
            )
            VALUES (?,?,?,?)
        """, (
            user_id,
            utc_now_iso(),
            body.latitude,
            body.longitude
        ))

        session = db.execute("""
            SELECT *
            FROM presence
            WHERE id=?
        """, (cursor.lastrowid,)).fetchone()

        db.commit()

        return {
            "message": "Checked in",
            "session": dict(session),
            "state": "IN"
        }

    except sqlite3.IntegrityError:
        active = db.execute("""
            SELECT *
            FROM presence
            WHERE user_id=?
            AND verify_out_time IS NULL
            LIMIT 1
        """, (user_id,)).fetchone()

        db.rollback()

        return {
            "message": "Already checked in",
            "session": dict(active),
            "state": "IN"
        }
    finally:
        db.close()

@app.post("/api/verifyout")
def verifyout(body: VerifyinBody, token=Depends(decode_token)):
    if token["role"] != "user":
        raise HTTPException(403, "Users only")

    db = get_db()
    user_id = int(token["sub"])

    try:
        db.execute("BEGIN IMMEDIATE")

        auto_close_abandoned_sessions(db)

        row = db.execute("""
            SELECT *
            FROM presence
            WHERE user_id=?
            AND verify_out_time IS NULL
            ORDER BY verify_in_time DESC
            LIMIT 1
        """, (user_id,)).fetchone()

        if not row:
            db.rollback()
            raise HTTPException(400, "No active session")

        settings = db.execute(
            "SELECT * FROM location_settings WHERE id=1"
        ).fetchone()

        if settings:
            dist = distance_meters(
                body.latitude,
                body.longitude,
                settings["latitude"],
                settings["longitude"],
            )

            if dist > settings["radius_meters"]:
                db.rollback()
                raise HTTPException(400, "Outside allowed location")

        checkout_time = utc_now_iso()

        db.execute("""
            UPDATE presence
            SET verify_out_time=?,
                closed_reason=?
            WHERE id=?
            AND verify_out_time IS NULL
        """, (
            checkout_time,
            "USER_CHECKOUT",
            row["id"]
        ))

        session = db.execute("""
            SELECT *
            FROM presence
            WHERE id=?
        """, (row["id"],)).fetchone()

        db.commit()

        return {
            "message": "Checked out",
            "session": dict(session),
            "state": "OUT"
        }
    finally:
        db.close()

@app.get("/api/my-presence")
def my_presence(token=Depends(decode_token)):
    if token["role"] != "user":
        raise HTTPException(403, "Users only")
    db = get_db()
    rows = db.execute("SELECT * FROM presence WHERE user_id=? ORDER BY verify_in_time DESC",
                      (int(token["sub"]),)).fetchall()
    db.close()
    
    return [dict(r) for r in rows]

# ── ORGANIZATION ROUTES ───────────────────────────────────────
@app.post("/api/location-settings")
def save_location_settings(body: LocationSettingsBody, token=Depends(decode_token)):
    if token["role"] != "organization":
        raise HTTPException(403, "Organizations only")

    db = get_db()
    db.execute("""
        INSERT OR REPLACE INTO location_settings
        (id, start_time, end_time, latitude, longitude, radius_meters)
        VALUES (1, ?, ?, ?, ?, ?)
    """, (
        body.start_time,
        body.end_time,
        body.latitude,
        body.longitude,
        body.radius_meters,
    ))
    db.commit()
    db.close()
    return {"message": "location settings saved"}

@app.get("/api/location-settings")
def get_location_settings(token=Depends(decode_token)):
    if token["role"] != "organization":
        raise HTTPException(403, "Organizations only")

    db = get_db()
    row = db.execute(
        "SELECT * FROM location_settings WHERE id=1"
    ).fetchone()
    db.close()
    return dict(row) if row else {}

@app.get("/api/public-location-settings")
def public_location_settings():
    db = get_db()

    row = db.execute("""
        SELECT start_time, end_time
        FROM location_settings
        WHERE id=1
    """).fetchone()

    db.close()

    return dict(row) if row else {}

@app.get("/api/users")
def list_users(token=Depends(decode_token)):
    if token["role"] != "organization":
        raise HTTPException(403, "Organizations only")
    db = get_db()
    rows = db.execute("SELECT id, username FROM users WHERE role='user'").fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.get("/api/presence/{user_id}")
def user_presence(user_id: int, token=Depends(decode_token)):
    if token["role"] != "organization":
        raise HTTPException(403, "Organizations only")
    db = get_db()
    rows = db.execute("SELECT * FROM presence WHERE user_id=? ORDER BY verify_in_time DESC",
                      (user_id,)).fetchall()
    db.close()
    
    return [dict(r) for r in rows]

# ── SERVE FRONTEND ────────────────────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def root():
    return FileResponse(INDEX_FILE)

@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    if full_path.startswith("api/"):
        raise HTTPException(404, "Not found")
    return FileResponse(INDEX_FILE)
