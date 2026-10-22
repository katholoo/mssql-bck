"""История действий пользователей (SQLite)."""
import datetime
import json
import os
import sqlite3
import threading

from config import DATA_DIR

DB_PATH = os.path.join(DATA_DIR, "history.db")
KEEP_DAYS = int(os.environ.get("HISTORY_KEEP_DAYS", "365"))
_lock = threading.RLock()
_conn = None

SCHEMA = """
CREATE TABLE IF NOT EXISTS history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    finished  TEXT,
    username  TEXT NOT NULL,
    source    TEXT NOT NULL DEFAULT '',
    role      TEXT NOT NULL DEFAULT '',
    ip        TEXT NOT NULL DEFAULT '',
    action    TEXT NOT NULL,
    target    TEXT NOT NULL DEFAULT '',
    status    TEXT NOT NULL DEFAULT 'ok',
    details   TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS history_ts ON history(ts DESC);
CREATE INDEX IF NOT EXISTS history_status ON history(status);
"""

COLUMNS = ("id", "ts", "finished", "username", "source", "role", "ip", "action", "target", "status", "details")


def _now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _db():
    global _conn
    if _conn is None:
        os.makedirs(DATA_DIR, exist_ok=True)
        _conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        _conn.execute("PRAGMA journal_mode=WAL")
        _conn.executescript(SCHEMA)
        # Миграция с прошлых версий: параметры задач очереди (status = 'queued')
        if "params" not in {r[1] for r in _conn.execute("PRAGMA table_info(history)")}:
            _conn.execute("ALTER TABLE history ADD COLUMN params TEXT")
            _conn.commit()
        try:
            os.chmod(DB_PATH, 0o600)
        except OSError:
            pass
    return _conn


def _row(r):
    return dict(zip(COLUMNS, r))


def startup():
    """Помечает оборванные операции и чистит старые записи."""
    with _lock:
        db = _db()
        db.execute(
            "UPDATE history SET status='interrupted', finished=?, "
            "details=CASE WHEN details='' THEN 'Сервис был перезапущен во время операции' ELSE details END "
            "WHERE status='running'", (_now(),))
        cutoff = (datetime.datetime.now(datetime.timezone.utc)
                  - datetime.timedelta(days=KEEP_DAYS)).strftime("%Y-%m-%dT%H:%M:%SZ")
        db.execute("DELETE FROM history WHERE ts < ?", (cutoff,))
        db.commit()


def add(user, action, target="", status="ok", details="", ip=""):
    """user: словарь с ключами name/source/role (как в сессии)."""
    finished = None if status in ("running", "queued") else _now()
    with _lock:
        db = _db()
        cur = db.execute(
            "INSERT INTO history (ts, finished, username, source, role, ip, action, target, status, details) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (_now(), finished, str(user.get("name", ""))[:100], user.get("source", ""), user.get("role", ""),
             ip[:64], action, str(target)[:300], status, str(details)[:2000]))
        db.commit()
        return cur.lastrowid


def finish(hid, status, details=""):
    with _lock:
        db = _db()
        db.execute("UPDATE history SET status=?, finished=?, details=? WHERE id=?",
                   (status, _now(), str(details)[:2000], hid))
        db.commit()


def get(hid):
    with _lock:
        r = _db().execute("SELECT %s FROM history WHERE id=?" % ",".join(COLUMNS), (hid,)).fetchone()
    return _row(r) if r else None


def has_running():
    with _lock:
        r = _db().execute(
            "SELECT 1 FROM history WHERE status='running' AND action IN ('backup','restore') LIMIT 1").fetchone()
    return r is not None


def query(limit=100, offset=0, action="", user="", status=""):
    where, args = [], []
    if action:
        where.append("action = ?")
        args.append(action)
    if status:
        where.append("status = ?")
        args.append(status)
    if user:
        where.append("username LIKE ?")
        args.append("%" + user.replace("%", "") + "%")
    sql = "SELECT %s FROM history" % ",".join(COLUMNS)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    with _lock:
        rows = _db().execute(sql, args + [limit + 1, offset]).fetchall()
    items = [_row(r) for r in rows[:limit]]
    return items, len(rows) > limit


# Общее соединение и блокировка для модуля access (таблицы пользователей, групп и запросов)
lock = _lock


def conn():
    return _db()


# ---------- очередь задач ----------
# Задача очереди — запись истории со статусом queued (ждёт) → running (выполняется) → ok / error / cancelled.
# Параметры хранятся в JSON (без секретов: настройки хранилища читаются при выполнении).
JOB_ACTIONS = ("backup", "restore")


def enqueue(user, action, target, params, details="", ip=""):
    with _lock:
        db = _db()
        cur = db.execute(
            "INSERT INTO history (ts, finished, username, source, role, ip, action, target, status, details, params) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (_now(), None, str(user.get("name", ""))[:100], user.get("source", ""), user.get("role", ""),
             ip[:64], action, str(target)[:300], "queued", str(details)[:2000], json.dumps(params, ensure_ascii=False)))
        db.commit()
        return cur.lastrowid


def claim_next():
    """Берёт самую старую ожидающую задачу и помечает её выполняющейся. None — очередь пуста."""
    with _lock:
        db = _db()
        r = db.execute("SELECT id, action, target, username, source, role, details, params FROM history "
                       "WHERE status='queued' ORDER BY id LIMIT 1").fetchone()
        if not r:
            return None
        if db.execute("UPDATE history SET status='running' WHERE id=? AND status='queued'", (r[0],)).rowcount != 1:
            return None
        db.commit()
    try:
        params = json.loads(r[7] or "{}")
    except ValueError:
        params = {}
    return {"id": r[0], "action": r[1], "target": r[2], "username": r[3], "source": r[4], "role": r[5],
            "details": r[6], "params": params}


def position(hid):
    """Место в очереди: 1 — выполняется сейчас или следующая."""
    with _lock:
        return _db().execute(
            "SELECT COUNT(*) FROM history WHERE action IN ('backup','restore') "
            "AND status IN ('queued','running') AND id <= ?", (hid,)).fetchone()[0]


def queue_snapshot(recent=20):
    cols = ",".join(COLUMNS)
    with _lock:
        db = _db()
        active = db.execute("SELECT %s FROM history WHERE action IN ('backup','restore') AND status IN ('queued','running') "
                            "ORDER BY CASE status WHEN 'running' THEN 0 ELSE 1 END, id" % cols).fetchall()
        done = db.execute("SELECT %s FROM history WHERE action IN ('backup','restore') "
                          "AND status NOT IN ('queued','running') ORDER BY id DESC LIMIT ?" % cols, (recent,)).fetchall()
    return [_row(r) for r in active], [_row(r) for r in done]


def recent_jobs(limit=50, offset=0, action="", status="", user="", target="", text="", date_from="", date_to="",
                own=None, python_text=None):
    """Завершённые задачи очереди с фильтрами по столбцам. own — ключ (логин в нижнем регистре): только его задачи.
    python_text — функция(строка_результата) -> bool вместо SQL-поиска по тексту результата (нужна, когда пользователь
    видит результат в сокращённом виде и искать по скрытой части нельзя). Возвращает (список, есть_ещё)."""
    where = ["action IN ('backup','restore')", "status NOT IN ('queued','running')"]
    args = []
    if own is not None:
        where.append("LOWER(TRIM(username)) = ?")
        args.append(own)
    for col, val in (("action", action), ("status", status)):
        if val:
            where.append(col + " = ?")
            args.append(val)
    for col, val in (("username", user), ("target", target)):
        if val:
            where.append(col + " LIKE ?")
            args.append("%" + val.replace("%", "") + "%")
    if text and python_text is None:
        where.append("details LIKE ?")
        args.append("%" + text.replace("%", "") + "%")
    if date_from:
        where.append("COALESCE(finished, ts) >= ?")
        args.append(date_from)
    if date_to:
        where.append("COALESCE(finished, ts) < ?")
        args.append(date_to)
    sql = "SELECT %s FROM history WHERE %s ORDER BY id DESC" % (",".join(COLUMNS), " AND ".join(where))
    with _lock:
        if python_text is None:
            rows = _db().execute(sql + " LIMIT ? OFFSET ?", args + [limit + 1, offset]).fetchall()
            items = [_row(r) for r in rows]
            return items[:limit], len(items) > limit
        items = [_row(r) for r in _db().execute(sql, args).fetchall()]
    items = [i for i in items if python_text(i["details"])]
    return items[offset:offset + limit], len(items) > offset + limit


def cancel_queued(hid):
    """Снимает задачу с очереди, пока она не началась. False — уже выполняется или завершена."""
    with _lock:
        db = _db()
        n = db.execute("UPDATE history SET status='cancelled', finished=? WHERE id=? AND status='queued'",
                       (_now(), hid)).rowcount
        db.commit()
    return n == 1
