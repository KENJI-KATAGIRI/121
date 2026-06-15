from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, RedirectResponse
import urllib.parse
from pydantic import BaseModel
from typing import Optional
import sqlite3
from pathlib import Path
import os
import json
import tempfile
import httpx
import hashlib
import secrets
import datetime

app = FastAPI(title="BNI Manager")
BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "data" / "bni.db"
GOOGLE_REDIRECT_URI = "https://life-energy-coaching.net/bni/api/auth/google/callback"


def get_db():
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT DEFAULT '',
            pw_hash TEXT NOT NULL,
            pw_salt TEXT NOT NULL,
            profile_data TEXT DEFAULT '{}',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER DEFAULT 1,
            name TEXT NOT NULL,
            reading TEXT DEFAULT '',
            company TEXT DEFAULT '',
            chapter TEXT DEFAULT '',
            category TEXT DEFAULT '',
            last_meeting_date TEXT DEFAULT '',
            business_description TEXT DEFAULT '',
            area TEXT DEFAULT '',
            birthplace TEXT DEFAULT '',
            residence TEXT DEFAULT '',
            spouse TEXT DEFAULT '',
            family TEXT DEFAULT '',
            previous_jobs TEXT DEFAULT '',
            hobbies TEXT DEFAULT '',
            experience_years TEXT DEFAULT '',
            success_key TEXT DEFAULT '',
            selling_points TEXT DEFAULT '',
            target_customers TEXT DEFAULT '',
            referral_intro TEXT DEFAULT '',
            request TEXT DEFAULT '',
            goals TEXT DEFAULT '',
            accomplishments TEXT DEFAULT '',
            interests TEXT DEFAULT '',
            networks TEXT DEFAULT '',
            skills TEXT DEFAULT '',
            introduction TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS memos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS reminders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            contact_id INTEGER NOT NULL,
            remind_date TEXT NOT NULL,
            message TEXT DEFAULT '',
            done INTEGER DEFAULT 0,
            FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS google_tokens (
            user_id INTEGER PRIMARY KEY,
            access_token TEXT,
            refresh_token TEXT,
            connected_at TEXT DEFAULT (datetime('now','localtime'))
        );
        CREATE TABLE IF NOT EXISTS referrals (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contact_id INTEGER NOT NULL,
            direction TEXT NOT NULL DEFAULT 'given',
            date TEXT DEFAULT '',
            description TEXT DEFAULT '',
            result TEXT DEFAULT '進行中',
            amount INTEGER DEFAULT 0,
            created_at TEXT DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (contact_id) REFERENCES contacts(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS one_on_ones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            contact_id INTEGER,
            contact_name TEXT DEFAULT '',
            meeting_date TEXT DEFAULT (date('now','localtime')),
            duration_minutes REAL DEFAULT 0,
            transcript TEXT DEFAULT '',
            summary TEXT DEFAULT '',
            gains_goals TEXT DEFAULT '',
            gains_accomplishments TEXT DEFAULT '',
            gains_interests TEXT DEFAULT '',
            gains_networks TEXT DEFAULT '',
            gains_skills TEXT DEFAULT '',
            referral_hints TEXT DEFAULT '',
            follow_up TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime'))
        );
    """)
    # 既存テーブルへのカラム追加（マイグレーション）
    for sql in [
        "ALTER TABLE contacts ADD COLUMN user_id INTEGER DEFAULT 1",
        "ALTER TABLE one_on_ones ADD COLUMN follow_up TEXT DEFAULT ''",
    ]:
        try: conn.execute(sql)
        except: pass
    conn.commit()
    conn.close()


init_db()

# ── 認証 ──────────────────────────────────────────────────
active_sessions: dict = {}  # token -> user_id
oauth_states: dict = {}     # state -> user_id (Google OAuth用)

def hash_pw(password: str, salt: str = None):
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return h, salt

def verify_pw(password: str, hashed: str, salt: str) -> bool:
    return hash_pw(password, salt)[0] == hashed

def init_default_user():
    conn = get_db()
    row = conn.execute("SELECT id FROM users LIMIT 1").fetchone()
    if not row:
        h, s = hash_pw('bni2024')
        conn.execute("INSERT INTO users (username,display_name,pw_hash,pw_salt) VALUES (?,?,?,?)",
                     ('admin', '管理者', h, s))
        conn.commit()
        # 既存コンタクトをadminに割り当て
        conn.execute("UPDATE contacts SET user_id=1 WHERE user_id IS NULL OR user_id=1")
        conn.commit()
    conn.close()

init_default_user()

def get_uid(request: Request) -> int:
    return active_sessions.get(request.headers.get('authorization',''), 0)

class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        open_paths = ('/api/auth/', '/profile/')
        if path.startswith('/api/') and not any(path.startswith(p) for p in open_paths):
            if request.headers.get('authorization','') not in active_sessions:
                return JSONResponse(status_code=401, content={"detail": "認証が必要です"})
        return await call_next(request)

app.add_middleware(AuthMiddleware)


class ContactIn(BaseModel):
    name: str
    reading: Optional[str] = ''
    company: Optional[str] = ''
    chapter: Optional[str] = ''
    category: Optional[str] = ''
    last_meeting_date: Optional[str] = ''
    business_description: Optional[str] = ''
    area: Optional[str] = ''
    birthplace: Optional[str] = ''
    residence: Optional[str] = ''
    spouse: Optional[str] = ''
    family: Optional[str] = ''
    previous_jobs: Optional[str] = ''
    hobbies: Optional[str] = ''
    experience_years: Optional[str] = ''
    success_key: Optional[str] = ''
    selling_points: Optional[str] = ''
    target_customers: Optional[str] = ''
    referral_intro: Optional[str] = ''
    request: Optional[str] = ''
    goals: Optional[str] = ''
    accomplishments: Optional[str] = ''
    interests: Optional[str] = ''
    networks: Optional[str] = ''
    skills: Optional[str] = ''
    introduction: Optional[str] = ''


class MemoIn(BaseModel):
    content: str


class ReminderIn(BaseModel):
    remind_date: str
    message: Optional[str] = ''


class ReferralIn(BaseModel):
    direction: str
    date: Optional[str] = ''
    description: Optional[str] = ''
    result: Optional[str] = '進行中'
    amount: Optional[int] = 0


# ── Contacts ──────────────────────────────────────────────
@app.get("/api/contacts")
def list_contacts(request: Request, q: str = ''):
    conn = get_db()
    uid = get_uid(request)
    if q:
        like = f'%{q}%'
        rows = conn.execute(
            "SELECT * FROM contacts WHERE user_id=? AND (name LIKE ? OR company LIKE ? OR category LIKE ? OR chapter LIKE ?) ORDER BY updated_at DESC",
            (uid, like, like, like, like)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM contacts WHERE user_id=? ORDER BY updated_at DESC", (uid,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/contacts", status_code=201)
def create_contact(request: Request, c: ContactIn):
    uid = get_uid(request)
    conn = get_db()
    cur = conn.execute(
        """INSERT INTO contacts (user_id,name,reading,company,chapter,category,last_meeting_date,
           business_description,area,birthplace,residence,spouse,family,previous_jobs,hobbies,
           experience_years,success_key,selling_points,target_customers,referral_intro,request,
           goals,accomplishments,interests,networks,skills,introduction)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (uid,c.name,c.reading,c.company,c.chapter,c.category,c.last_meeting_date,
         c.business_description,c.area,c.birthplace,c.residence,c.spouse,c.family,
         c.previous_jobs,c.hobbies,c.experience_years,c.success_key,c.selling_points,
         c.target_customers,c.referral_intro,c.request,c.goals,c.accomplishments,
         c.interests,c.networks,c.skills,c.introduction)
    )
    conn.commit()
    row = conn.execute("SELECT * FROM contacts WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.close()
    return dict(row)


@app.get("/api/contacts/{cid}")
def get_contact(request: Request, cid: int):
    uid = get_uid(request)
    conn = get_db()
    row = conn.execute("SELECT * FROM contacts WHERE id=? AND user_id=?", (cid, uid)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404)
    return dict(row)


@app.put("/api/contacts/{cid}")
def update_contact(request: Request, cid: int, c: ContactIn):
    uid = get_uid(request)
    conn = get_db()
    conn.execute(
        """UPDATE contacts SET name=?,reading=?,company=?,chapter=?,category=?,last_meeting_date=?,
           business_description=?,area=?,birthplace=?,residence=?,spouse=?,family=?,previous_jobs=?,
           hobbies=?,experience_years=?,success_key=?,selling_points=?,target_customers=?,
           referral_intro=?,request=?,goals=?,accomplishments=?,interests=?,networks=?,skills=?,
           introduction=?,updated_at=datetime('now','localtime') WHERE id=? AND user_id=?""",
        (c.name,c.reading,c.company,c.chapter,c.category,c.last_meeting_date,
         c.business_description,c.area,c.birthplace,c.residence,c.spouse,c.family,
         c.previous_jobs,c.hobbies,c.experience_years,c.success_key,c.selling_points,
         c.target_customers,c.referral_intro,c.request,c.goals,c.accomplishments,
         c.interests,c.networks,c.skills,c.introduction,cid,uid)
    )
    conn.commit()
    row = conn.execute("SELECT * FROM contacts WHERE id=?", (cid,)).fetchone()
    conn.close()
    return dict(row)


@app.delete("/api/contacts/{cid}")
def delete_contact(request: Request, cid: int):
    uid = get_uid(request)
    conn = get_db()
    conn.execute("DELETE FROM contacts WHERE id=? AND user_id=?", (cid, uid))
    conn.commit()
    conn.close()
    return {"ok": True}


# ── Memos ─────────────────────────────────────────────────
@app.get("/api/contacts/{cid}/memos")
def list_memos(cid: int):
    conn = get_db()
    rows = conn.execute("SELECT * FROM memos WHERE contact_id=? ORDER BY created_at DESC", (cid,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/contacts/{cid}/memos", status_code=201)
def create_memo(cid: int, m: MemoIn):
    conn = get_db()
    cur = conn.execute("INSERT INTO memos (contact_id,content) VALUES (?,?)", (cid, m.content))
    conn.commit()
    row = conn.execute("SELECT * FROM memos WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.close()
    return dict(row)


@app.delete("/api/memos/{mid}")
def delete_memo(mid: int):
    conn = get_db()
    conn.execute("DELETE FROM memos WHERE id=?", (mid,))
    conn.commit()
    conn.close()
    return {"ok": True}


# ── Reminders ─────────────────────────────────────────────
@app.get("/api/contacts/{cid}/reminders")
def list_reminders(cid: int):
    conn = get_db()
    rows = conn.execute("SELECT * FROM reminders WHERE contact_id=? ORDER BY remind_date", (cid,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/contacts/{cid}/reminders", status_code=201)
async def create_reminder(request: Request, cid: int, r: ReminderIn):
    uid = get_uid(request)
    conn = get_db()
    contact = conn.execute("SELECT name FROM contacts WHERE id=?", (cid,)).fetchone()
    cur = conn.execute("INSERT INTO reminders (contact_id,remind_date,message) VALUES (?,?,?)",
                       (cid, r.remind_date, r.message))
    conn.commit()
    row = conn.execute("SELECT * FROM reminders WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.close()
    result = dict(row)
    if contact and uid:
        event_url = await create_google_calendar_event(uid, f"1on1: {contact['name']}", r.remind_date, r.message or '')
        if event_url:
            result['google_event_url'] = event_url
    return result


@app.put("/api/reminders/{rid}/toggle")
def toggle_reminder(rid: int):
    conn = get_db()
    conn.execute("UPDATE reminders SET done = 1 - done WHERE id=?", (rid,))
    conn.commit()
    row = conn.execute("SELECT * FROM reminders WHERE id=?", (rid,)).fetchone()
    conn.close()
    return dict(row)


@app.delete("/api/reminders/{rid}")
def delete_reminder(rid: int):
    conn = get_db()
    conn.execute("DELETE FROM reminders WHERE id=?", (rid,))
    conn.commit()
    conn.close()
    return {"ok": True}


# ── 認証エンドポイント ────────────────────────────────────

class LoginIn(BaseModel):
    username: str
    password: str

class RegisterIn(BaseModel):
    username: str
    display_name: str
    password: str

class ChangePwIn(BaseModel):
    current_password: str
    new_password: str

@app.post("/api/auth/login")
def login(data: LoginIn):
    conn = get_db()
    row = conn.execute("SELECT id,pw_hash,pw_salt,display_name FROM users WHERE username=?", (data.username,)).fetchone()
    conn.close()
    if not row or not verify_pw(data.password, row[1], row[2]):
        raise HTTPException(401, detail="ユーザー名またはパスワードが違います")
    token = secrets.token_hex(32)
    active_sessions[token] = row[0]
    return {"token": token, "display_name": row[3], "username": data.username}

@app.post("/api/auth/register")
def register(data: RegisterIn):
    if len(data.password) < 6:
        raise HTTPException(400, detail="パスワードは6文字以上にしてください")
    h, s = hash_pw(data.password)
    conn = get_db()
    try:
        conn.execute("INSERT INTO users (username,display_name,pw_hash,pw_salt) VALUES (?,?,?,?)",
                     (data.username.strip(), data.display_name.strip(), h, s))
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(400, detail="そのユーザー名は既に使われています")
    finally:
        conn.close()
    return {"ok": True}

@app.post("/api/auth/logout")
def logout(request: Request):
    active_sessions.pop(request.headers.get('authorization',''), None)
    return {"ok": True}

@app.post("/api/auth/change-password")
def change_password(request: Request, data: ChangePwIn):
    uid = get_uid(request)
    conn = get_db()
    row = conn.execute("SELECT pw_hash,pw_salt FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not row or not verify_pw(data.current_password, row[0], row[1]):
        raise HTTPException(400, detail="現在のパスワードが違います")
    new_h, new_s = hash_pw(data.new_password)
    conn = get_db()
    conn.execute("UPDATE users SET pw_hash=?,pw_salt=? WHERE id=?", (new_h, new_s, uid))
    conn.commit()
    conn.close()
    return {"ok": True}


# ── ダッシュボード ─────────────────────────────────────────

@app.get("/api/dashboard")
def dashboard(request: Request):
    uid = get_uid(request)
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM contacts WHERE user_id=?", (uid,)).fetchone()[0]
    reminders = conn.execute(
        "SELECT COUNT(*) FROM reminders r JOIN contacts c ON c.id=r.contact_id WHERE c.user_id=? AND r.done=0", (uid,)
    ).fetchone()[0]
    chapters = conn.execute("SELECT COUNT(DISTINCT chapter) FROM contacts WHERE user_id=? AND chapter!=''", (uid,)).fetchone()[0]
    monthly = conn.execute("""
        SELECT substr(last_meeting_date,1,7) as m, COUNT(*) as cnt
        FROM contacts WHERE user_id=? AND last_meeting_date!='' AND last_meeting_date IS NOT NULL
        GROUP BY m ORDER BY m DESC LIMIT 12
    """, (uid,)).fetchall()
    upcoming = conn.execute("""
        SELECT r.remind_date, r.message, c.name FROM reminders r
        JOIN contacts c ON c.id=r.contact_id
        WHERE c.user_id=? AND r.done=0 ORDER BY r.remind_date LIMIT 5
    """, (uid,)).fetchall()
    conn.close()
    return {
        "total_contacts": total,
        "pending_reminders": reminders,
        "chapters": chapters,
        "monthly": [{"month": r[0], "count": r[1]} for r in reversed(list(monthly))],
        "upcoming_reminders": [{"date": r[0], "message": r[1], "name": r[2]} for r in upcoming]
    }


# ── マイプロフィール ───────────────────────────────────────

@app.get("/api/my-profile")
def get_my_profile(request: Request):
    uid = get_uid(request)
    conn = get_db()
    row = conn.execute("SELECT profile_data, username, display_name FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    if not row: return {}
    d = json.loads(row[0] or '{}')
    d['username'] = row[1]
    d['display_name'] = row[2]
    return d

@app.put("/api/my-profile")
async def update_my_profile(request: Request):
    uid = get_uid(request)
    data = await request.json()
    display_name = data.get('display_name', '')
    profile_json = json.dumps(data, ensure_ascii=False)
    conn = get_db()
    conn.execute("UPDATE users SET profile_data=?, display_name=? WHERE id=?", (profile_json, display_name, uid))
    conn.commit()
    conn.close()
    return data

@app.get("/api/public-profile")
def public_profile_data():
    data = get_setting('my_profile_data')
    if not data:
        raise HTTPException(404)
    p = json.loads(data)
    if not p.get('public', False):
        raise HTTPException(404, detail="プロフィールは非公開です")
    return p

@app.get("/profile/{slug}")
def public_profile_page(slug: str):
    stored_slug = get_setting('profile_slug') or 'my-profile'
    if slug != stored_slug:
        raise HTTPException(404)
    data = get_setting('my_profile_data')
    if not data:
        raise HTTPException(404)
    p = json.loads(data)
    if not p.get('public', False):
        return HTMLResponse("<h2>このプロフィールは非公開です</h2>", status_code=403)
    name = p.get('name','')
    category = p.get('category','')
    company = p.get('company','')
    chapter = p.get('chapter','')
    business = p.get('business_description','').replace('\n','<br>')
    selling = p.get('selling_points','').replace('\n','<br>')
    target = p.get('target_customers','').replace('\n','<br>')
    referral = p.get('referral_intro','').replace('\n','<br>')
    html = f"""<!DOCTYPE html>
<html lang="ja"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{name} | BNI プロフィール</title>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="bg-gray-50 min-h-screen">
<div class="max-w-2xl mx-auto py-10 px-4">
  <div class="bg-white rounded-2xl shadow p-8">
    <h1 class="text-2xl font-bold text-gray-900">{name}</h1>
    <div class="text-blue-600 font-medium mt-1">{category}</div>
    <div class="text-gray-500 text-sm mt-0.5">{company}{' / ' + chapter if chapter else ''}</div>
    {'<hr class="my-5"><h2 class="font-bold text-gray-700 mb-2">事業内容</h2><p class="text-sm text-gray-800">' + business + '</p>' if business else ''}
    {'<hr class="my-5"><h2 class="font-bold text-gray-700 mb-2">独自の強み</h2><p class="text-sm text-gray-800">' + selling + '</p>' if selling else ''}
    {'<hr class="my-5"><h2 class="font-bold text-gray-700 mb-2">こんな方を探しています</h2><p class="text-sm text-gray-800">' + target + '</p>' if target else ''}
    {'<hr class="my-5"><h2 class="font-bold text-gray-700 mb-2">紹介の切り出し方</h2><p class="text-sm text-gray-800">' + referral + '</p>' if referral else ''}
  </div>
</div></body></html>"""
    return HTMLResponse(html)


# ── AI 紹介文生成 ─────────────────────────────────────────
@app.post("/api/contacts/{cid}/generate-introduction")
def generate_introduction(cid: int):
    conn = get_db()
    row = conn.execute("SELECT * FROM contacts WHERE id=?", (cid,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404)
    c = dict(row)

    openai_env = Path.home() / '.secrets' / 'openai.env'
    if openai_env.exists():
        for line in openai_env.read_text().splitlines():
            if line.startswith('OPENAI_API_KEY='):
                os.environ['OPENAI_API_KEY'] = line.split('=', 1)[1].strip('"\'')

    try:
        from openai import OpenAI
        client = OpenAI()
        prompt = f"""以下のBNIメンバーの情報をもとに、他のメンバーが紹介するための自然な紹介文を200字程度で作成してください。

名前: {c.get('name','')}
職種: {c.get('category','')}
会社名: {c.get('company','')}
事業内容: {c.get('business_description','')}
独自の強み: {c.get('selling_points','')}
ターゲット顧客: {c.get('target_customers','')}
紹介の切り出し方: {c.get('referral_intro','')}

BNIメンバーが実際に使える、自然で簡潔な紹介文を書いてください。"""

        res = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=400
        )
        text = res.choices[0].message.content.strip()

        db = get_db()
        db.execute("UPDATE contacts SET introduction=?,updated_at=datetime('now','localtime') WHERE id=?", (text, cid))
        db.commit()
        db.close()
        return {"introduction": text}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


# ── Googleカレンダー連携 ───────────────────────────────────

def load_google_credentials():
    google_env = Path.home() / '.secrets' / 'google.env'
    if google_env.exists():
        for line in google_env.read_text().splitlines():
            if '=' in line and not line.startswith('#'):
                key, val = line.split('=', 1)
                os.environ[key.strip()] = val.strip().strip('"\'')


async def create_google_calendar_event(uid: int, title: str, date: str, description: str = '') -> str | None:
    conn = get_db()
    row = conn.execute("SELECT access_token, refresh_token FROM google_tokens WHERE user_id=?", (uid,)).fetchone()
    conn.close()
    if not row:
        return None

    load_google_credentials()
    client_id = os.environ.get('GOOGLE_CLIENT_ID', '')
    client_secret = os.environ.get('GOOGLE_CLIENT_SECRET', '')
    event_body = {"summary": title, "description": description,
                  "start": {"date": date}, "end": {"date": date}}

    async with httpx.AsyncClient() as client:
        r = await client.post(
            'https://www.googleapis.com/calendar/v3/calendars/primary/events',
            json=event_body,
            headers={'Authorization': f'Bearer {row["access_token"]}'}
        )
        if r.status_code == 401:
            ref = await client.post('https://oauth2.googleapis.com/token', data={
                'refresh_token': row['refresh_token'],
                'client_id': client_id,
                'client_secret': client_secret,
                'grant_type': 'refresh_token'
            })
            if ref.status_code != 200:
                return None
            new_token = ref.json().get('access_token')
            conn = get_db()
            conn.execute("UPDATE google_tokens SET access_token=? WHERE user_id=?", (new_token, uid))
            conn.commit()
            conn.close()
            r = await client.post(
                'https://www.googleapis.com/calendar/v3/calendars/primary/events',
                json=event_body,
                headers={'Authorization': f'Bearer {new_token}'}
            )
        if r.status_code in (200, 201):
            return r.json().get('htmlLink')
    return None


@app.get("/api/auth/google/calendar")
def google_calendar_connect(request: Request, token: str = ''):
    uid = active_sessions.get(token) or get_uid(request)
    if not uid:
        raise HTTPException(401)
    load_google_credentials()
    client_id = os.environ.get('GOOGLE_CLIENT_ID', '')
    if not client_id:
        raise HTTPException(500, detail="Google認証が未設定です")
    state = secrets.token_hex(16)
    oauth_states[state] = uid
    params = {
        'client_id': client_id,
        'redirect_uri': GOOGLE_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'https://www.googleapis.com/auth/calendar.events',
        'access_type': 'offline',
        'prompt': 'consent',
        'state': state
    }
    return RedirectResponse('https://accounts.google.com/o/oauth2/v2/auth?' + urllib.parse.urlencode(params))


@app.get("/api/auth/google/callback")
async def google_calendar_callback(code: str = None, state: str = None, error: str = None):
    base_url = "https://life-energy-coaching.net/bni/"
    if error or not code or not state:
        return RedirectResponse(base_url + "?google_error=1")
    uid = oauth_states.pop(state, None)
    if not uid:
        return RedirectResponse(base_url + "?google_error=1")
    load_google_credentials()
    async with httpx.AsyncClient() as client:
        r = await client.post('https://oauth2.googleapis.com/token', data={
            'code': code,
            'client_id': os.environ.get('GOOGLE_CLIENT_ID', ''),
            'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET', ''),
            'redirect_uri': GOOGLE_REDIRECT_URI,
            'grant_type': 'authorization_code'
        })
    if r.status_code != 200:
        return RedirectResponse(base_url + "?google_error=1")
    tokens = r.json()
    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO google_tokens (user_id, access_token, refresh_token) VALUES (?,?,?)",
        (uid, tokens.get('access_token', ''), tokens.get('refresh_token', ''))
    )
    conn.commit()
    conn.close()
    return RedirectResponse(base_url + "?google_connected=1")


@app.get("/api/auth/google/status")
def google_calendar_status(request: Request):
    uid = get_uid(request)
    conn = get_db()
    row = conn.execute("SELECT connected_at FROM google_tokens WHERE user_id=?", (uid,)).fetchone()
    conn.close()
    return {"connected": row is not None, "connected_at": row['connected_at'] if row else None}


@app.delete("/api/auth/google/calendar")
def google_calendar_disconnect(request: Request):
    uid = get_uid(request)
    conn = get_db()
    conn.execute("DELETE FROM google_tokens WHERE user_id=?", (uid,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/reminders/{rid}/sync-google")
async def sync_reminder_google(request: Request, rid: int):
    uid = get_uid(request)
    conn = get_db()
    row = conn.execute(
        "SELECT r.*, c.name as contact_name FROM reminders r JOIN contacts c ON c.id=r.contact_id WHERE r.id=?",
        (rid,)
    ).fetchone()
    conn.close()
    if not row:
        raise HTTPException(404)
    url = await create_google_calendar_event(uid, f"1on1: {row['contact_name']}", row['remind_date'], row['message'] or '')
    if not url:
        raise HTTPException(400, detail="Googleカレンダーへの同期に失敗しました。連携を確認してください。")
    return {"event_url": url}


# ── Referrals ─────────────────────────────────────────────
@app.get("/api/contacts/{cid}/referrals")
def list_referrals(cid: int):
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM referrals WHERE contact_id=? ORDER BY date DESC, created_at DESC", (cid,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.post("/api/contacts/{cid}/referrals", status_code=201)
def create_referral(request: Request, cid: int, r: ReferralIn):
    uid = get_uid(request)
    conn = get_db()
    cur = conn.execute(
        "INSERT INTO referrals (user_id,contact_id,direction,date,description,result,amount) VALUES (?,?,?,?,?,?,?)",
        (uid, cid, r.direction, r.date, r.description, r.result, r.amount)
    )
    conn.commit()
    row = conn.execute("SELECT * FROM referrals WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.close()
    return dict(row)


@app.put("/api/referrals/{rid}")
def update_referral(rid: int, r: ReferralIn):
    conn = get_db()
    conn.execute(
        "UPDATE referrals SET direction=?,date=?,description=?,result=?,amount=? WHERE id=?",
        (r.direction, r.date, r.description, r.result, r.amount, rid)
    )
    conn.commit()
    row = conn.execute("SELECT * FROM referrals WHERE id=?", (rid,)).fetchone()
    conn.close()
    return dict(row)


@app.delete("/api/referrals/{rid}")
def delete_referral(rid: int):
    conn = get_db()
    conn.execute("DELETE FROM referrals WHERE id=?", (rid,))
    conn.commit()
    conn.close()
    return {"ok": True}


# ── カレンダー ────────────────────────────────────────────
@app.get("/api/calendar/google")
async def get_google_calendar_events(request: Request, year: int, month: int):
    uid = get_uid(request)
    conn = get_db()
    row = conn.execute("SELECT access_token, refresh_token FROM google_tokens WHERE user_id=?", (uid,)).fetchone()
    conn.close()
    if not row:
        return {"events": [], "connected": False}

    load_google_credentials()
    time_min = f"{year}-{month:02d}-01T00:00:00Z"
    next_y, next_m = (year + 1, 1) if month == 12 else (year, month + 1)
    time_max = f"{next_y}-{next_m:02d}-01T00:00:00Z"

    async def fetch_events(token):
        async with httpx.AsyncClient() as client:
            return await client.get(
                'https://www.googleapis.com/calendar/v3/calendars/primary/events',
                params={'timeMin': time_min, 'timeMax': time_max,
                        'singleEvents': 'true', 'orderBy': 'startTime', 'maxResults': 200},
                headers={'Authorization': f'Bearer {token}'}
            )

    r = await fetch_events(row['access_token'])
    if r.status_code == 401:
        async with httpx.AsyncClient() as client:
            ref = await client.post('https://oauth2.googleapis.com/token', data={
                'refresh_token': row['refresh_token'],
                'client_id': os.environ.get('GOOGLE_CLIENT_ID', ''),
                'client_secret': os.environ.get('GOOGLE_CLIENT_SECRET', ''),
                'grant_type': 'refresh_token'
            })
        if ref.status_code != 200:
            return {"events": [], "connected": True, "error": "トークンの更新に失敗しました"}
        new_token = ref.json().get('access_token')
        conn = get_db()
        conn.execute("UPDATE google_tokens SET access_token=? WHERE user_id=?", (new_token, uid))
        conn.commit()
        conn.close()
        r = await fetch_events(new_token)

    if r.status_code != 200:
        return {"events": [], "connected": True, "error": "Googleカレンダーの取得に失敗しました"}

    events = []
    for item in r.json().get('items', []):
        s = item.get('start', {})
        date = s.get('date') or (s.get('dateTime', '')[:10])
        events.append({
            'id': item.get('id', ''),
            'title': item.get('summary', '(タイトルなし)'),
            'date': date,
            'url': item.get('htmlLink', ''),
            'time': s.get('dateTime', '')
        })
    return {"events": events, "connected": True}


@app.get("/api/calendar")
def get_calendar(request: Request, year: int, month: int):
    uid = get_uid(request)
    month_str = f"{year}-{month:02d}"
    conn = get_db()
    reminders = conn.execute("""
        SELECT r.id, r.remind_date, r.message, r.done, c.name as contact_name, c.id as contact_id
        FROM reminders r JOIN contacts c ON c.id=r.contact_id
        WHERE c.user_id=? AND r.remind_date LIKE ?
        ORDER BY r.remind_date
    """, (uid, f"{month_str}%")).fetchall()
    meetings = conn.execute("""
        SELECT id, name, category, company, last_meeting_date
        FROM contacts WHERE user_id=? AND last_meeting_date LIKE ?
        ORDER BY last_meeting_date
    """, (uid, f"{month_str}%")).fetchall()
    conn.close()
    return {
        "reminders": [dict(r) for r in reminders],
        "meetings": [dict(m) for m in meetings]
    }


# ── 1on1優先度サジェスト ───────────────────────────────────
@app.get("/api/suggestions/next-meetings")
def suggest_next_meetings(request: Request):
    uid = get_uid(request)
    conn = get_db()
    contacts = conn.execute("SELECT * FROM contacts WHERE user_id=?", (uid,)).fetchall()
    today = datetime.date.today()
    results = []

    for c in [dict(r) for r in contacts]:
        days_since = None
        if c.get('last_meeting_date'):
            try:
                last = datetime.date.fromisoformat(c['last_meeting_date'])
                days_since = (today - last).days
            except Exception:
                pass

        ref_count = conn.execute(
            "SELECT COUNT(*) FROM referrals WHERE contact_id=?", (c['id'],)
        ).fetchone()[0]

        overdue = conn.execute(
            "SELECT COUNT(*) FROM reminders WHERE contact_id=? AND done=0 AND remind_date<=?",
            (c['id'], str(today))
        ).fetchone()[0]

        if days_since is None:
            day_score, reason = 60, "まだ1on1をしていません"
        elif days_since >= 180:
            day_score, reason = 50, f"{days_since}日間1on1をしていません"
        elif days_since >= 90:
            day_score, reason = 35, f"{days_since}日ぶりの1on1が必要です"
        elif days_since >= 30:
            day_score, reason = 20, f"最終1on1から{days_since}日経過"
        else:
            day_score, reason = max(0, days_since // 2), f"{days_since}日前に会いました"

        score = day_score + min(ref_count * 5, 20) + overdue * 15

        tags = []
        if days_since is None:
            tags.append("未1on1")
        elif days_since >= 90:
            tags.append(f"{days_since}日経過")
        if overdue:
            tags.append(f"期限切れリマインダー×{overdue}")
        if ref_count:
            tags.append(f"紹介{ref_count}件")

        results.append({
            "contact": {"id": c['id'], "name": c['name'], "category": c.get('category',''), "company": c.get('company','')},
            "score": score,
            "reason": reason,
            "tags": tags,
            "days_since": days_since,
            "ref_count": ref_count
        })

    conn.close()
    results.sort(key=lambda x: x['score'], reverse=True)
    return results[:10]


# ── AIマッチング ──────────────────────────────────────────
@app.post("/api/contacts/{cid}/match")
def match_contacts(request: Request, cid: int):
    uid = get_uid(request)
    conn = get_db()
    target = conn.execute("SELECT * FROM contacts WHERE id=? AND user_id=?", (cid, uid)).fetchone()
    if not target:
        raise HTTPException(404)
    others = conn.execute(
        "SELECT * FROM contacts WHERE user_id=? AND id!=? ORDER BY updated_at DESC LIMIT 30",
        (uid, cid)
    ).fetchall()
    conn.close()

    if not others:
        return {"matches": []}

    t = dict(target)
    target_summary = f"""名前: {t.get('name','')}
職種: {t.get('category','')}
事業内容: {t.get('business_description','')}
独自の強み: {t.get('selling_points','')}
ターゲット顧客: {t.get('target_customers','')}
目標: {t.get('goals','')}
スキル: {t.get('skills','')}
人脈: {t.get('networks','')}"""

    others_list = [dict(r) for r in others]
    others_summary = "\n\n".join([
        f"ID:{o['id']} 名前:{o.get('name','')} 職種:{o.get('category','')} "
        f"事業:{o.get('business_description','')[:200]} "
        f"強み:{o.get('selling_points','')[:150]} "
        f"ターゲット:{o.get('target_customers','')[:150]} "
        f"目標:{o.get('goals','')[:100]}"
        for o in others_list
    ])

    prompt = f"""あなたはBNIのビジネスマッチングAIです。
【対象者】と最も相性の良い人を【候補者リスト】から選び、上位3名をJSONで返してください。

【対象者】
{target_summary}

【候補者リスト】
{others_summary}

評価基準：
1. 紹介し合える可能性（互いのターゲット顧客・事業内容の親和性）
2. ビジネスシナジー（補完関係、協業可能性）
3. GAINS共通点（目標・興味・スキルの一致）

出力JSON:
{{"matches":[{{"contact_id":<ID>,"score":<1-100>,"reason":"<50字程度の理由>","referral_opportunity":"<具体的な紹介シナリオ>"}}]}}

上位3名のみ、JSONのみ返してください。"""

    load_openai()
    try:
        from openai import OpenAI
        client = OpenAI()
        res = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=1000,
            response_format={"type": "json_object"}
        )
        data = json.loads(res.choices[0].message.content)
        matches = data.get('matches', [])

        id_map = {o['id']: o for o in others_list}
        result = []
        for m in matches:
            mid = m.get('contact_id')
            if mid in id_map:
                o = id_map[mid]
                result.append({
                    "contact": {"id": o['id'], "name": o.get('name',''), "category": o.get('category',''), "company": o.get('company','')},
                    "score": m.get('score', 0),
                    "reason": m.get('reason', ''),
                    "referral_opportunity": m.get('referral_opportunity', '')
                })
        return {"matches": result}
    except Exception as e:
        raise HTTPException(500, detail=str(e))


# ── インポート ────────────────────────────────────────────

def load_openai():
    openai_env = Path.home() / '.secrets' / 'openai.env'
    if openai_env.exists():
        for line in openai_env.read_text().splitlines():
            if line.startswith('OPENAI_API_KEY='):
                os.environ['OPENAI_API_KEY'] = line.split('=', 1)[1].strip('"\'')


def extract_text_from_pdf(path: str) -> str:
    import pdfplumber
    text = []
    with pdfplumber.open(path) as pdf:
        for page in pdf.pages:
            t = page.extract_text()
            if t:
                text.append(t)
    return '\n'.join(text)


def extract_text_from_docx(path: str) -> str:
    from docx import Document
    doc = Document(path)
    return '\n'.join(p.text for p in doc.paragraphs if p.text.strip())


def clean_csv_text(text: str) -> str:
    """CSV形式の空行・空カラムを除去して読みやすいテキストに変換"""
    import csv, io
    lines = []
    try:
        reader = csv.reader(io.StringIO(text))
        for row in reader:
            cells = [c.strip() for c in row if c.strip()]
            if cells:
                lines.append('  '.join(cells))
    except Exception:
        # CSV解析に失敗したらそのまま返す
        return text
    return '\n'.join(lines)


def parse_with_ai(text: str) -> dict:
    load_openai()
    from openai import OpenAI
    client = OpenAI()

    prompt = f"""あなたはBNIメンバー管理システムのデータ抽出AIです。
以下のテキストはBNIの「メンバー略歴シート」または「Power 1-2-1シート」または「GAINSシート」です。
内容を解析して指定のフィールドにマッピングし、JSONで返してください。

【BNI書類の対応表】
メンバー略歴シート:
  「スピーカー：」→ name
  「チャプター」→ chapter
  「事業名：」→ company
  「専門分野：」→ category（職種・カテゴリー）
  「経験年数：」→ experience_years
  「所在地：」→ area
  「過去に経験した職業：」→ previous_jobs
  「配偶者：」→ spouse
  「その他家族：」→ family
  「出身地：」→ birthplace
  「居住地：」→ residence
  「趣味：」→ hobbies
  「私の成功の鍵は」→ success_key

Power 1-2-1シート（番号付き項目）:
  「1.氏名」「1.名前」→ name
  「2.会社名または屋号」→ company
  「３．専門分野、中心的なサービス」→ business_description（長文でもそのまま全文入れる）
  「４．他社にない強み」→ selling_points（長文でもそのまま全文入れる）
  「５．どんな人、どんな会社が良いクライアントになりますか」→ target_customers（長文でもそのまま全文入れる）
  「６．あなたについて、どう会話を切り出したらよいですか」→ referral_intro（長文でもそのまま全文入れる）

GAINSシート:
  「Goals（目標）」→ goals
  「Accomplishments（実績）」→ accomplishments
  「Interests（興味関心）」→ interests
  「Networks（人脈）」→ networks
  「Skills（スキル）」→ skills

【重要ルール】
- 長い説明文・箇条書きはそのまま全文を入れる（省略しない）
- 項目が見当たらない場合は空文字列
- 数字付き項目（１、２、３...）はPower 1-2-1の項目番号として解釈する
- 複数のシートが混在している場合はすべてのシートから抽出する

抽出フィールド（JSON keys）:
name, reading, company, chapter, category, business_description, area, birthplace, residence,
spouse, family, previous_jobs, hobbies, experience_years,
success_key, selling_points, target_customers, referral_intro, request,
goals, accomplishments, interests, networks, skills

テキスト（最大10000文字）:
{text[:10000]}

JSONのみ返してください。"""

    res = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=3000,
        response_format={"type": "json_object"}
    )
    raw = res.choices[0].message.content.strip()
    return json.loads(raw)


@app.post("/api/import/file")
async def import_file(file: UploadFile = File(...)):
    suffix = Path(file.filename).suffix.lower()
    if suffix not in ('.pdf', '.docx', '.doc', '.txt'):
        raise HTTPException(400, detail="対応形式: PDF, DOCX, TXT")

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    try:
        if suffix == '.pdf':
            text = extract_text_from_pdf(tmp_path)
        elif suffix in ('.docx', '.doc'):
            text = extract_text_from_docx(tmp_path)
        else:
            text = Path(tmp_path).read_text(encoding='utf-8', errors='ignore')

        if not text.strip():
            raise HTTPException(400, detail="テキストを抽出できませんでした")

        if ',,' in text[:200]:
            text = clean_csv_text(text)

        parsed = parse_with_ai(text)
        return {"parsed": parsed, "raw_text": text[:1200]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=str(e))
    finally:
        os.unlink(tmp_path)


def extract_text_from_xlsx(data: bytes) -> str:
    """XLSXの全シートからテキストを抽出"""
    import openpyxl, io
    wb = openpyxl.load_workbook(io.BytesIO(data), data_only=True)
    parts = []
    for sheet_name in wb.sheetnames:
        ws = wb[sheet_name]
        sheet_lines = [f"=== シート: {sheet_name} ==="]
        for row in ws.iter_rows(values_only=True):
            cells = [str(c).strip() for c in row if c is not None and str(c).strip() and str(c).strip() != 'None']
            if cells:
                sheet_lines.append('  '.join(cells))
        if len(sheet_lines) > 1:
            parts.append('\n'.join(sheet_lines))
    return '\n\n'.join(parts)


@app.post("/api/import/url")
async def import_url(url: str = Form(...)):
    export_url = url
    is_sheets = 'docs.google.com/spreadsheets' in url

    if 'docs.google.com/document' in url:
        doc_id = url.split('/d/')[1].split('/')[0]
        export_url = f'https://docs.google.com/document/d/{doc_id}/export?format=txt'
    elif is_sheets:
        sheet_id = url.split('/d/')[1].split('/')[0]
        export_url = f'https://docs.google.com/spreadsheets/d/{sheet_id}/export?format=xlsx'

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=30) as client:
            r = await client.get(export_url)
        if r.status_code != 200:
            raise HTTPException(400, detail=f"取得失敗 (HTTP {r.status_code})。ファイルが「リンクを知っている人全員が閲覧可能」に設定されているか確認してください。")

        content = r.content
        content_type = r.headers.get('content-type', '')

        if 'html' in content_type or b'accounts.google.com' in content[:500]:
            raise HTTPException(400, detail="Googleのログイン画面が返されました。ファイルの共有設定を「リンクを知っている人全員が閲覧可能」に変更してください。")

        if is_sheets or 'spreadsheet' in content_type or content[:4] == b'PK\x03\x04':
            text = extract_text_from_xlsx(content)
        else:
            text = r.text
            if ',,' in text[:200]:
                text = clean_csv_text(text)

        parsed = parse_with_ai(text)
        return {"parsed": parsed, "raw_text": text[:1200]}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, detail=str(e))


# ── NiceMeet BNI連携 ─────────────────────────────────────
@app.post("/api/nicemeet-webhook")
async def nicemeet_webhook(request: Request):
    secret = request.headers.get("x-nicemeet-secret", "")
    expected = os.environ.get("NICEMEET_WEBHOOK_SECRET", "nicemeet-bni-2026")
    if secret != expected:
        raise HTTPException(403, detail="forbidden")
    data = await request.json()
    conn = get_db()
    user = conn.execute("SELECT id FROM users WHERE username=?", (data.get("bni_user",""),)).fetchone()
    if not user:
        conn.close()
        raise HTTPException(404, detail="user not found")
    uid = user["id"]
    contact_id = data.get("contact_id")
    if contact_id:
        c = conn.execute("SELECT id FROM contacts WHERE id=? AND user_id=?", (contact_id, uid)).fetchone()
        if not c:
            contact_id = None
    gains = data.get("gains", {})
    conn.execute("""
        INSERT INTO one_on_ones (user_id, contact_id, contact_name, duration_minutes, transcript, summary,
            gains_goals, gains_accomplishments, gains_interests, gains_networks, gains_skills,
            referral_hints, follow_up)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (uid, contact_id, data.get("contact_name",""), data.get("duration_minutes", 0),
          data.get("transcript",""), data.get("summary",""),
          gains.get("goals",""), gains.get("accomplishments",""), gains.get("interests",""),
          gains.get("networks",""), gains.get("skills",""),
          data.get("referral_hints",""), data.get("follow_up","")))
    conn.commit()
    if contact_id and any(gains.values()):
        c = conn.execute("SELECT goals,accomplishments,interests,networks,skills FROM contacts WHERE id=?", (contact_id,)).fetchone()
        updates = {}
        for f in ["goals","accomplishments","interests","networks","skills"]:
            if not c[f] and gains.get(f):
                updates[f] = gains[f]
        if updates:
            set_clause = ", ".join(f"{k}=?" for k in updates)
            conn.execute(f"UPDATE contacts SET {set_clause}, updated_at=datetime('now','localtime') WHERE id=?",
                         list(updates.values()) + [contact_id])
            conn.commit()
    conn.close()
    return {"ok": True}

@app.get("/api/contacts/{cid}/one-on-ones")
def get_contact_one_on_ones(cid: int, request: Request):
    uid = get_uid(request)
    if not uid:
        raise HTTPException(401)
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM one_on_ones WHERE contact_id=? AND user_id=? ORDER BY created_at DESC",
        (cid, uid)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/api/one-on-ones")
def get_all_one_on_ones(request: Request):
    uid = get_uid(request)
    if not uid:
        raise HTTPException(401)
    conn = get_db()
    rows = conn.execute("""
        SELECT o.*, COALESCE(c.name, o.contact_name) as contact_display, c.company
        FROM one_on_ones o
        LEFT JOIN contacts c ON o.contact_id = c.id
        WHERE o.user_id=?
        ORDER BY o.created_at DESC LIMIT 100
    """, (uid,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ── Static / SPA ─────────────────────────────────────────
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/")
def root():
    return FileResponse(str(BASE_DIR / "static" / "index.html"))


@app.get("/{path:path}")
def spa(path: str):
    return FileResponse(str(BASE_DIR / "static" / "index.html"))
