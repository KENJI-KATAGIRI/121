from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Request
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse
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

app = FastAPI(title="BNI Manager")
BASE_DIR = Path(__file__).parent
DB_PATH = BASE_DIR / "data" / "bni.db"


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
    """)
    # 既存テーブルへのカラム追加（マイグレーション）
    for sql in [
        "ALTER TABLE contacts ADD COLUMN user_id INTEGER DEFAULT 1",
    ]:
        try: conn.execute(sql)
        except: pass
    conn.commit()
    conn.close()


init_db()

# ── 認証 ──────────────────────────────────────────────────
active_sessions: dict = {}  # token -> user_id

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
def create_reminder(cid: int, r: ReminderIn):
    conn = get_db()
    cur = conn.execute("INSERT INTO reminders (contact_id,remind_date,message) VALUES (?,?,?)",
                       (cid, r.remind_date, r.message))
    conn.commit()
    row = conn.execute("SELECT * FROM reminders WHERE id=?", (cur.lastrowid,)).fetchone()
    conn.close()
    return dict(row)


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


# ── Static / SPA ─────────────────────────────────────────
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


@app.get("/")
def root():
    return FileResponse(str(BASE_DIR / "static" / "index.html"))


@app.get("/{path:path}")
def spa(path: str):
    return FileResponse(str(BASE_DIR / "static" / "index.html"))
