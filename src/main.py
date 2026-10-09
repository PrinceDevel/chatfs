import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager

from fasthtml.common import *
from starlette.responses import RedirectResponse, Response

from datatypes import Message, User

# ───────────────────────────── Database ─────────────────────────────

DB_PATH = os.getenv("CHATFS_DB", "chatfs.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL UNIQUE COLLATE NOCASE,
    passhash TEXT NOT NULL,
    created  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS messages(
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id   INTEGER NOT NULL REFERENCES users(id),
    receiver_id INTEGER NOT NULL REFERENCES users(id),
    body        TEXT NOT NULL,
    ts          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, receiver_id, id);
"""


@contextmanager
def db():
    """One short-lived connection per operation (safe across FastHTML's threadpool)."""
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys = ON")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


with db() as _c:
    _c.execute("PRAGMA journal_mode = WAL")
    _c.executescript(SCHEMA)


def get_user(uid) -> User | None:
    with db() as c:
        r = c.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return User(**dict(r)) if r else None


def contacts(me_id: int) -> list[dict]:
    """Every other user, people you've talked to first (most recent on top)."""
    pair = "((m.sender_id = :me AND m.receiver_id = u.id) OR (m.sender_id = u.id AND m.receiver_id = :me))"
    with db() as c:
        rows = c.execute(
            f"""SELECT u.id, u.name,
                       (SELECT m.body FROM messages m WHERE {pair} ORDER BY m.id DESC LIMIT 1) AS preview,
                       (SELECT MAX(m.id) FROM messages m WHERE {pair}) AS last_id
                FROM users u WHERE u.id != :me
                ORDER BY last_id IS NULL, last_id DESC, u.name""",
            {"me": me_id},
        ).fetchall()
    return [dict(r) for r in rows]


def thread(a: int, b: int, after: int = 0, limit: int = 100) -> list[Message]:
    """Messages exchanged between users a and b ONLY, oldest first."""
    with db() as c:
        rows = c.execute(
            """SELECT * FROM (
                   SELECT * FROM messages
                   WHERE id > ? AND ((sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?))
                   ORDER BY id DESC LIMIT ?
               ) ORDER BY id""",
            (after, a, b, b, a, limit),
        ).fetchall()
    return [Message(**dict(r)) for r in rows]


# ───────────────────────────── Passwords ─────────────────────────────

_SCRYPT = dict(n=2**14, r=8, p=1)


def hash_password(pw: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(pw.encode(), salt=salt, **_SCRYPT)
    return f"scrypt${salt.hex()}${h.hex()}"


def verify_password(pw: str, stored: str) -> bool:
    try:
        _, salt, h = stored.split("$")
        calc = hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), **_SCRYPT)
        return hmac.compare_digest(calc.hex(), h)
    except ValueError:
        return False


# Verified against when the username doesn't exist, so response time doesn't leak which names are taken.
DUMMY_HASH = hash_password(secrets.token_hex(8))

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
MIN_PASSWORD = 8
MAX_MESSAGE = 2000

# Tiny in-memory brute-force guard: 5 failed logins per 5 minutes per (ip, username).
_fails: dict[str, list[float]] = {}


def throttled(key: str) -> bool:
    now = time.time()
    hits = [t for t in _fails.get(key, []) if now - t < 300]
    _fails[key] = hits
    return len(hits) >= 5


# ───────────────────────────── App + auth middleware ─────────────────────────────

CSS = """
:root{--bg:#0b0b14;--panel:#111116;--panel2:#1a1a24;--line:#2d2d3d;--text:#ececf4;--muted:#8d8da3;
      --accent:#ff4b4b;--accent-ink:#1a0505;--mine:#5C1D16;--theirs:#1d1d2a}
*{box-sizing:border-box}
html,body{margin:0;height:100%;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,"Segoe UI",sans-serif}
a{color:var(--accent)}
input{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:8px;padding:11px 12px;font:inherit;width:100%}
input:focus-visible,button:focus-visible,a:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
button{background:var(--accent);color:var(--accent-ink);border:0;border-radius:8px;padding:11px 18px;font:inherit;font-weight:700;cursor:pointer}
button:hover{filter:brightness(1.08)}
button.ghost{background:transparent;color:var(--muted);border:1px solid var(--line);padding:6px 10px;font-weight:500;font-size:.85rem}

/* auth pages */
.auth-wrap{max-width:400px;margin:10vh auto;padding:32px;background:var(--panel);border:1px solid var(--line);border-radius:14px}
.auth-wrap img{display:block;width:70%;margin:0 auto 22px}
.auth-wrap h2{margin:0 0 18px;text-align:center;font-size:1.15rem;font-weight:600}
.auth-wrap form{display:flex;flex-direction:column;gap:12px}
.auth-wrap label{font-size:.85rem;color:var(--muted);display:flex;flex-direction:column;gap:5px}
.auth-wrap .alt{margin:18px 0 0;text-align:center;color:var(--muted);font-size:.9rem}
.error{background:#3a1414;border:1px solid #7a2424;color:#ffb4b4;padding:10px 12px;border-radius:8px;font-size:.9rem;margin-bottom:14px}
.hint{font-size:.78rem;color:var(--muted)}

/* app shell */
.app{display:flex;gap:.5em;padding:.5em;height:100vh;height:100dvh}
.sidebar{width:300px;flex:none;background:var(--panel);border:1px solid var(--line);border-radius:12px;display:flex;flex-direction:column;overflow:hidden}
.sidebar .logo{width:70%;margin:18px auto 14px;display:block}
.me{display:flex;align-items:center;gap:10px;padding:10px 14px;border-top:1px solid var(--line);border-bottom:1px solid var(--line)}
.me form{margin:0}
.me .grow{flex:1;min-width:0}
.search{padding:10px 12px}
#contacts{flex:1;overflow-y:auto}
.contact{display:flex;gap:10px;align-items:center;padding:10px 14px;text-decoration:none;color:var(--text);border-left:3px solid transparent}
.contact:hover{background:var(--panel2)}
.contact.active{background:var(--panel2);border-left-color:var(--accent)}
.c-meta{min-width:0}
.c-name{font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.c-prev{color:var(--muted);font-size:.82rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.avatar{width:38px;height:38px;flex:none;border-radius:50%;background:var(--mine);color:#ffd9d4;display:grid;place-items:center;font-weight:700}
.empty-note{color:var(--muted);padding:18px 14px;font-size:.9rem;margin:0}

.panel{flex:1;min-width:0;background:var(--panel);border:1px solid var(--line);border-radius:12px;display:flex;flex-direction:column;overflow:hidden}
.panel-empty{margin:auto;color:var(--muted);text-align:center;padding:20px}
.chat-head{display:flex;align-items:center;gap:12px;padding:12px 16px;border-bottom:1px solid var(--line)}
.chat-head h3{margin:0;font-size:1.05rem}
.back{display:none;text-decoration:none;font-size:1.4rem;color:var(--muted)}
#chat-box{flex:1;overflow-y:auto;padding:18px;display:flex;flex-direction:column;gap:6px}
.msg{max-width:min(70%,560px);display:flex;flex-direction:column}
.msg.mine{align-self:flex-end;align-items:flex-end}
.msg.theirs{align-self:flex-start}
.bubble{padding:8px 12px;border-radius:14px;line-height:1.4;white-space:pre-wrap;overflow-wrap:anywhere}
.mine .bubble{background:var(--mine);border-bottom-right-radius:4px}
.theirs .bubble{background:var(--theirs);border-bottom-left-radius:4px}
.ts{font-size:.7rem;color:var(--muted);margin:2px 4px 0}
.composer{display:flex;gap:10px;padding:12px;border-top:1px solid var(--line);margin:0}

@media (max-width:760px){
  .sidebar{width:100%}
  .panel{display:none}
  .app.has-chat .sidebar{display:none}
  .app.has-chat .panel{display:flex}
  .back{display:block}
  .msg{max-width:85%}
}
"""

JS = """
function lastMsgId(){const m=document.querySelectorAll('#chat-box [data-id]');return m.length?m[m.length-1].dataset.id:0}
function toBottom(){const b=document.getElementById('chat-box');if(b)b.scrollTop=b.scrollHeight}
function fmtTimes(root){
  (root||document).querySelectorAll('.ts[data-ts]:not([data-done])').forEach(el=>{
    const d=new Date(el.dataset.ts*1000), same=d.toDateString()===new Date().toDateString();
    el.textContent=same?d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}):d.toLocaleString([],{dateStyle:'short',timeStyle:'short'});
    el.dataset.done=1;
  });
}
function filterContacts(q){
  q=(q||'').trim().toLowerCase();
  document.querySelectorAll('#contacts .contact').forEach(a=>{a.style.display=a.dataset.name.includes(q)?'':'none'});
}
let stick=true;
document.addEventListener('htmx:beforeSwap',e=>{
  if(e.target.id==='chat-box') stick=e.target.scrollHeight-e.target.scrollTop-e.target.clientHeight<120;
});
document.addEventListener('htmx:afterSwap',e=>{
  if(e.target.id==='chat-box'){fmtTimes(e.target);if(stick)toBottom()}
  if(e.target.id==='contacts'){const s=document.getElementById('search');filterContacts(s?s.value:'')}
});
document.addEventListener('DOMContentLoaded',()=>{fmtTimes();toBottom()});
"""


def auth_before(req, sess):
    """Runs before every protected route: must be logged in as a user that still exists."""
    user = get_user(sess.get("auth")) if sess.get("auth") is not None else None
    if user is None:
        sess.pop("auth", None)
        if req.headers.get("HX-Request"):  # htmx polling: bounce the whole page to /login
            return Response(status_code=401, headers={"HX-Redirect": "/login"})
        return RedirectResponse("/login", status_code=303)
    req.scope["auth"] = user  # handlers receive it via an `auth` parameter


beforeware = Beforeware(
    auth_before,
    skip=[r"/favicon\.ico", r"/static/.*", r".*\.(png|jpg|jpeg|svg|gif|css|js|ico)$", "/login", "/register"],
)

app, rt = fast_app(
    before=beforeware,
    hdrs=(Style(NotStr(CSS)), Script(NotStr(JS)), Meta(name="viewport", content="width=device-width, initial-scale=1")),
    pico=False,
    static_path="public",
    max_age=60 * 60 * 24 * 30,  # stay logged in for 30 days
    same_site="lax",
    sess_https_only=os.getenv("CHATFS_HTTPS") == "1",  # set CHATFS_HTTPS=1 when served over HTTPS
)


# ───────────────────────────── Auth pages ─────────────────────────────

def auth_page(mode: str, error: str | None = None, username: str = ""):
    login = mode == "login"
    fields = [
        Label("Username", Input(name="username", value=username, required=True, autofocus=True,
                                autocomplete="username", maxlength="20")),
        Label("Password", Input(type="password", name="password", required=True, minlength="1" if login else str(MIN_PASSWORD),
                                autocomplete="current-password" if login else "new-password")),
    ]
    if not login:
        fields.append(Label("Confirm password", Input(type="password", name="confirm", required=True,
                                                       autocomplete="new-password")))
        fields.append(Div(f"3-20 letters, numbers or underscores. Password: {MIN_PASSWORD}+ characters.", cls="hint"))
    return (
        Title("CHATFS - " + ("Log in" if login else "Create account")),
        Main(
            Div(
                Img(src="/logo.png", alt="CHATFS"),
                H2("Log in" if login else "Create your account"),
                Div(error, cls="error", role="alert") if error else None,
                Form(*fields, Button("Log in" if login else "Create account", type="submit"),
                     method="post", action="/login" if login else "/register"),
                P("New here? ", A("Create an account", href="/register"), cls="alt") if login
                else P("Already registered? ", A("Log in", href="/login"), cls="alt"),
                cls="auth-wrap",
            )
        ),
    )


@app.get("/login")
def login_form(sess):
    if sess.get("auth") is not None and get_user(sess["auth"]):
        return RedirectResponse("/", status_code=303)
    return auth_page("login")


@app.post("/login")
def login_submit(request, sess, username: str = "", password: str = ""):
    username = username.strip()
    ip = request.client.host if request.client else "?"
    key = f"{ip}:{username.lower()}"
    if throttled(key):
        return auth_page("login", "Too many failed attempts. Try again in a few minutes.", username)

    with db() as c:
        row = c.execute("SELECT * FROM users WHERE name = ?", (username,)).fetchone()
    ok = verify_password(password, row["passhash"] if row else DUMMY_HASH)
    if not (row and ok):
        _fails.setdefault(key, []).append(time.time())
        return auth_page("login", "Wrong username or password.", username)

    _fails.pop(key, None)
    sess.clear()  # fresh session on login
    sess["auth"] = row["id"]
    return RedirectResponse("/", status_code=303)


@app.get("/register")
def register_form(sess):
    if sess.get("auth") is not None and get_user(sess["auth"]):
        return RedirectResponse("/", status_code=303)
    return auth_page("register")


@app.post("/register")
def register_submit(sess, username: str = "", password: str = "", confirm: str = ""):
    username = username.strip()
    error = None
    if not USERNAME_RE.match(username):
        error = "Username must be 3-20 characters: letters, numbers or underscores."
    elif len(password) < MIN_PASSWORD:
        error = f"Password must be at least {MIN_PASSWORD} characters."
    elif password != confirm:
        error = "Passwords don't match."
    if error:
        return auth_page("register", error, username)

    try:
        with db() as c:
            cur = c.execute("INSERT INTO users(name, passhash, created) VALUES (?, ?, ?)",
                            (username, hash_password(password), int(time.time())))
            uid = cur.lastrowid
    except sqlite3.IntegrityError:
        return auth_page("register", "That username is taken. Pick another one.", username)

    sess.clear()
    sess["auth"] = uid
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(sess):
    sess.clear()
    return RedirectResponse("/login", status_code=303)


# ───────────────────────────── Chat UI ─────────────────────────────

def bubble(m: Message, me_id: int):
    mine = m.sender_id == me_id
    return Div(
        Div(m.body, cls="bubble"),  # FastHTML escapes text, so user input can't inject HTML
        Span(cls="ts", data_ts=m.ts),
        cls="msg " + ("mine" if mine else "theirs"),
        data_id=m.id,
    )


def contact_links(me_id: int, active: int = 0):
    links = []
    for r in contacts(me_id):
        links.append(
            A(
                Div(r["name"][0].upper(), cls="avatar"),
                Div(Div(r["name"], cls="c-name"), Div((r["preview"] or "No messages yet")[:50], cls="c-prev"), cls="c-meta"),
                href=f"/chat/{r['id']}",
                cls="contact" + (" active" if r["id"] == active else ""),
                data_name=r["name"].lower(),
            )
        )
    return links or [P("No one else has joined yet. Share this app's link so a friend can register.", cls="empty-note")]


def shell(me: User, main_content, active: int = 0):
    return (
        Title("CHATFS"),
        Div(
            Aside(
                Img(src="/logo.png", alt="CHATFS", cls="logo"),
                Div(
                    Div(me.name[0].upper(), cls="avatar"),
                    Div(Div(me.name, cls="c-name"), Div("Signed in", cls="c-prev"), cls="grow"),
                    Form(Button("Log out", type="submit", cls="ghost"), method="post", action="/logout"),
                    cls="me",
                ),
                Div(Input(type="search", id="search", placeholder="Find a user...", oninput="filterContacts(this.value)",
                          autocomplete="off"), cls="search"),
                Div(*contact_links(me.id, active), id="contacts",
                    hx_get=f"/contacts?active={active}", hx_trigger="every 5s", hx_swap="innerHTML"),
                cls="sidebar",
            ),
            Main(main_content, cls="panel"),
            cls="app" + (" has-chat" if active else ""),
        ),
    )


@app.get("/")
def home(auth):
    return shell(auth, Div(H3("Pick someone to talk to"), P("Your conversations are private between you and them."),
                           cls="panel-empty"))


@app.get("/contacts")
def contacts_fragment(auth, active: int = 0):
    return tuple(contact_links(auth.id, active))


@app.get("/chat/{other_id}")
def chat(other_id: int, auth):
    other = get_user(other_id)
    if other is None or other.id == auth.id:
        return RedirectResponse("/", status_code=303)
    msgs = thread(auth.id, other.id)
    panel = Div(
        Div(A("←", href="/", cls="back", aria_label="Back to contacts"), Div(other.name[0].upper(), cls="avatar"),
            H3(other.name), cls="chat-head"),
        Div(*[bubble(m, auth.id) for m in msgs], id="chat-box",
            hx_get=f"/chat/{other.id}/poll", hx_trigger="every 2s, poll", hx_vals="js:{after: lastMsgId()}",
            hx_swap="beforeend", hx_sync="this:drop"),
        Form(
            Input(type="text", name="text", id="msg-input", placeholder=f"Message {other.name}", autocomplete="off",
                  maxlength=str(MAX_MESSAGE), required=True, autofocus=True),
            Button("Send", type="submit"),
            hx_post=f"/chat/{other.id}/send", hx_swap="none",
            hx_on__after_request="if(event.detail.successful){this.reset();htmx.trigger('#chat-box','poll')}",
            cls="composer",
        ),
        style="display:contents",
    )
    return shell(auth, panel, active=other.id)


@app.get("/chat/{other_id}/poll")
def poll(other_id: int, auth, after: int = 0):
    """New messages in THIS conversation only (query is scoped to the logged-in user and other_id)."""
    msgs = thread(auth.id, other_id, after)
    if not msgs:
        return Response(status_code=204)  # htmx leaves the page untouched
    return tuple(bubble(m, auth.id) for m in msgs)


@app.post("/chat/{other_id}/send")
def send(other_id: int, auth, text: str = ""):
    text = text.strip()
    if other_id == auth.id or get_user(other_id) is None:
        return Response("Unknown recipient", status_code=404)
    if not text or len(text) > MAX_MESSAGE:
        return Response("Invalid message", status_code=400)
    with db() as c:
        # sender comes from the session, never from the form, so it can't be spoofed
        c.execute("INSERT INTO messages(sender_id, receiver_id, body, ts) VALUES (?, ?, ?, ?)",
                  (auth.id, other_id, text, int(time.time())))
    return Response(status_code=204)


serve()
