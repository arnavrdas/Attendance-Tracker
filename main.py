# main.py
from fastapi import FastAPI, HTTPException, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta, time
from math import radians, sin, cos, sqrt, atan2
import sqlite3, hashlib, jwt, os

app = FastAPI()
SECRET = "change-this-secret-in-production"
ALGORITHM = "HS256"
DB = "presence.db"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
INDEX_FILE = os.path.join(BASE_DIR, "static", "index.html")
bearer = HTTPBearer()

# ── DB SETUP ──────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

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
            latitude REAL,
            longitude REAL,
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

    settings = db.execute(
        "SELECT * FROM location_settings WHERE id=1"
    ).fetchone()

    if settings:
        now = datetime.now().time()
        start = time.fromisoformat(settings["start_time"])
        end = time.fromisoformat(settings["end_time"])

        if start <= end:
            allowed = start <= now <= end
        else:
            allowed = now >= start or now <= end

        if not allowed:
            db.close()
            raise HTTPException(400, "Outside location hours")

        dist = distance_meters(
            body.latitude,
            body.longitude,
            settings["latitude"],
            settings["longitude"],
        )

        if dist > settings["radius_meters"]:
            db.close()
            raise HTTPException(400, "Outside allowed location radius")

    db.execute("INSERT INTO presence (user_id, verify_in_time, latitude, longitude) VALUES (?,?,?,?)",
               (int(token["sub"]), datetime.now().isoformat(), body.latitude, body.longitude))
    db.commit()
    db.close()
    return {"message": "Verified in"}

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
