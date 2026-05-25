# main.py
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from datetime import datetime, timedelta, time
from math import radians, sin, cos, sqrt, atan2
import sqlite3, hashlib, secrets, jwt, os

app = FastAPI()
SECRET = "change-this-secret-in-production"
ALGORITHM = "HS256"
DB = "attendance.db"
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
            role TEXT NOT NULL DEFAULT 'employee'
        );
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            checkin_time TEXT NOT NULL,
            latitude REAL,
            longitude REAL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS office_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            start_time TEXT NOT NULL,
            end_time TEXT NOT NULL,
            latitude REAL NOT NULL,
            longitude REAL NOT NULL,
            radius_meters REAL NOT NULL
        );
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
    role: str = "employee"  # used only for signup

class CheckinBody(BaseModel):
    latitude: float
    longitude: float

class OfficeSettingsBody(BaseModel):
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

# ── EMPLOYEE ROUTES ───────────────────────────────────────
@app.post("/api/checkin")
def checkin(body: CheckinBody, token=Depends(decode_token)):
    if token["role"] != "employee":
        raise HTTPException(403, "Employees only")
    db = get_db()

    settings = db.execute(
        "SELECT * FROM office_settings WHERE id=1"
    ).fetchone()

    if settings:
        now = datetime.now().time()
        start = time.fromisoformat(settings["start_time"])
        end = time.fromisoformat(settings["end_time"])

        if not (start <= now <= end):
            raise HTTPException(400, "Outside office hours")

        dist = distance_meters(
            body.latitude,
            body.longitude,
            settings["latitude"],
            settings["longitude"],
            settings["radius_meters"],
        )

        if dist > settings["radius_meters"]:
            raise HTTPException(400, "Outside allowed office radius")

    db.execute("INSERT INTO attendance (user_id, checkin_time, latitude, longitude) VALUES (?,?,?,?)",
               (int(token["sub"]), datetime.now().isoformat(), body.latitude, body.longitude))
    db.commit()
    db.close()
    return {"message": "Checked in"}

@app.get("/api/my-attendance")
def my_attendance(token=Depends(decode_token)):
    db = get_db()
    rows = db.execute("SELECT * FROM attendance WHERE user_id=? ORDER BY checkin_time DESC",
                      (int(token["sub"]),)).fetchall()
    db.close()
    return [dict(r) for r in rows]

# ── EMPLOYER ROUTES ───────────────────────────────────────
@app.post("/api/office-settings")
def save_office_settings(body: OfficeSettingsBody, token=Depends(decode_token)):
    if token["role"] != "employer":
        raise HTTPException(403, "Employers only")

    db = get_db()
    db.execute("""
        INSERT OR REPLACE INTO office_settings
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
    return {"message": "Office settings saved"}

@app.get("/api/office-settings")
def get_office_settings(token=Depends(decode_token)):
    if token["role"] != "employer":
        raise HTTPException(403, "Employers only")

    db = get_db()
    row = db.execute(
        "SELECT * FROM office_settings WHERE id=1"
    ).fetchone()
    db.close()
    return dict(row) if row else {}

@app.get("/api/employees")
def list_employees(token=Depends(decode_token)):
    if token["role"] != "employer":
        raise HTTPException(403, "Employers only")
    db = get_db()
    rows = db.execute("SELECT id, username FROM users WHERE role='employee'").fetchall()
    db.close()
    return [dict(r) for r in rows]

@app.get("/api/attendance/{user_id}")
def employee_attendance(user_id: int, token=Depends(decode_token)):
    if token["role"] != "employer":
        raise HTTPException(403, "Employers only")
    db = get_db()
    rows = db.execute("SELECT * FROM attendance WHERE user_id=? ORDER BY checkin_time DESC",
                      (user_id,)).fetchall()
    db.close()
    return [dict(r) for r in rows]

# ── SERVE FRONTEND ────────────────────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/{full_path:path}")
def serve_frontend(full_path: str):
    return FileResponse("static/index.html")
