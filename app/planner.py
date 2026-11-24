"""Отложенные копии: задание на создание копии базы в заданные дату и время (SQLite, рядом с историей).

Время хранится в UTC. Когда время наступает, планировщик (поток в app.py) ставит обычную задачу копирования в очередь
от имени автора — дальше всё как при ручном запуске (права, очередь, уведомления, история)."""
import datetime

import history

SCHEMA = """
CREATE TABLE IF NOT EXISTS scheduled (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    created   TEXT NOT NULL,
    run_at    TEXT NOT NULL,
    username  TEXT NOT NULL,
    source    TEXT NOT NULL DEFAULT '',
    role      TEXT NOT NULL DEFAULT '',
    database  TEXT NOT NULL,
    status    TEXT NOT NULL DEFAULT 'pending',
    job_id    INTEGER,
    note      TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS scheduled_run ON scheduled(status, run_at);
"""
COLS = ("id", "created", "run_at", "username", "source", "role", "database", "status", "job_id", "note")
MIN_AHEAD = 30                 # секунд: раньше, чем через полминуты, назначать нельзя
MAX_AHEAD_DAYS = 366
MAX_PENDING_PER_USER = 100
_ready = False


def _fmt(dt):
    return dt.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def parse_time(value):
    """ISO-строка с часовым поясом (или Z) -> aware datetime; иначе ValueError."""
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Не указано время запуска")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.datetime.fromisoformat(text)
    except ValueError:
        raise ValueError("Некорректные дата и время")
    if dt.tzinfo is None:
        raise ValueError("Время должно быть указано с часовым поясом")
    return dt


def _db():
    global _ready
    with history.lock:
        db = history.conn()
        if not _ready:
            db.executescript(SCHEMA)
            db.commit()
            _ready = True
        return db


def _key(name):
    return (name or "").strip().lower()


def add(user, database, run_at):
    """Создаёт отложенную копию. Возвращает id. ValueError — понятное сообщение для пользователя."""
    delta = (run_at - now()).total_seconds()
    if delta < MIN_AHEAD:
        raise ValueError("Время запуска должно быть в будущем (не раньше, чем через минуту)")
    if delta > MAX_AHEAD_DAYS * 86400:
        raise ValueError("Нельзя назначать копию дальше, чем на год вперёд")
    with history.lock:
        db = _db()
        n = db.execute("SELECT COUNT(*) FROM scheduled WHERE status='pending' AND lower(username)=?",
                       (_key(user["name"]),)).fetchone()[0]
        if n >= MAX_PENDING_PER_USER:
            raise ValueError("Слишком много отложенных копий (не больше %d)" % MAX_PENDING_PER_USER)
        rid = db.execute(
            "INSERT INTO scheduled (created, run_at, username, source, role, database) VALUES (?,?,?,?,?,?)",
            (history._now(), _fmt(run_at), user["name"], user.get("source", ""), user.get("role", ""), database)).lastrowid
        db.commit()
    return rid


def _rows(sql, args=()):
    with history.lock:
        return [dict(zip(COLS, r)) for r in _db().execute(
            "SELECT %s FROM scheduled %s" % (",".join(COLS), sql), args).fetchall()]


def get(rid):
    r = _rows("WHERE id=?", (rid,))
    return r[0] if r else None


def listing(username=None, recent_days=3):
    """Ожидающие и недавно сорвавшиеся/отменённые. username=None — все пользователи."""
    since = _fmt(now() - datetime.timedelta(days=recent_days))
    sql = "WHERE (status='pending' OR (status IN ('error','cancelled') AND run_at >= ?))"
    args = [since]
    if username is not None:
        sql += " AND lower(username)=?"
        args.append(_key(username))
    return _rows(sql + " ORDER BY run_at, id", args)


def cancel(rid):
    with history.lock:
        db = _db()
        n = db.execute("UPDATE scheduled SET status='cancelled' WHERE id=? AND status='pending'", (rid,)).rowcount
        db.commit()
    return n == 1


def claim_due(limit=20):
    """Забирает наступившие задания (pending -> starting). Каждое возвращается ровно один раз."""
    out = []
    with history.lock:
        db = _db()
        for r in _rows("WHERE status='pending' AND run_at <= ? ORDER BY run_at, id LIMIT ?", (_fmt(now()), limit)):
            if db.execute("UPDATE scheduled SET status='starting' WHERE id=? AND status='pending'", (r["id"],)).rowcount:
                out.append(r)
        db.commit()
    return out


def finish(rid, status, job_id=None, note=""):
    with history.lock:
        db = _db()
        db.execute("UPDATE scheduled SET status=?, job_id=?, note=? WHERE id=?", (status, job_id, note[:500], rid))
        db.commit()


def recover():
    """После перезапуска службы: задания, застрявшие в starting, возвращаются в ожидание."""
    with history.lock:
        db = _db()
        db.execute("UPDATE scheduled SET status='pending' WHERE status='starting'")
        db.commit()
