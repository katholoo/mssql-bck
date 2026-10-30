"""Пользователи (пополняются при первом входе из AD), внутренние группы и запросы на подтверждение.

Группы здесь — внутренние, не связанные с группами LDAP. Группа может:
  * разрешать восстановление в выбранные существующие базы;
  * подтверждать запросы на создание новых баз (approver).
Права пользователя на базы = его личный список + списки всех его групп.
"""
import json
import sqlite3

import history

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    name        TEXT PRIMARY KEY,
    display     TEXT NOT NULL DEFAULT '',
    source      TEXT NOT NULL DEFAULT '',
    role        TEXT NOT NULL DEFAULT '',
    dn          TEXT NOT NULL DEFAULT '',
    first_login TEXT NOT NULL,
    last_login  TEXT NOT NULL,
    allowed_dbs TEXT NOT NULL DEFAULT '[]',
    backup_dbs  TEXT NOT NULL DEFAULT '[]',
    source_dbs  TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    description TEXT NOT NULL DEFAULT '',
    approver    INTEGER NOT NULL DEFAULT 0,
    allowed_dbs TEXT NOT NULL DEFAULT '[]',
    backup_dbs  TEXT NOT NULL DEFAULT '[]',
    source_dbs  TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL,
    username TEXT NOT NULL,
    PRIMARY KEY (group_id, username)
);
CREATE TABLE IF NOT EXISTS requests (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    ts               TEXT NOT NULL,
    requester        TEXT NOT NULL,
    requester_name   TEXT NOT NULL,
    requester_source TEXT NOT NULL DEFAULT '',
    requester_role   TEXT NOT NULL DEFAULT '',
    path             TEXT NOT NULL,
    source_db        TEXT NOT NULL,
    target           TEXT NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending',
    decided_by       TEXT NOT NULL DEFAULT '',
    decided_ts       TEXT,
    comment          TEXT NOT NULL DEFAULT '',
    job_id           INTEGER
);
CREATE INDEX IF NOT EXISTS requests_status ON requests(status);
CREATE TABLE IF NOT EXISTS protected_dbs (
    name TEXT PRIMARY KEY
);
"""

_ready = False


def key(name):
    """Ключ пользователя: логин в нижнем регистре (в AD логины не зависят от регистра)."""
    return str(name or "").strip().lower()


def _db():
    global _ready
    with history.lock:
        db = history.conn()
        if not _ready:
            db.executescript(SCHEMA)
            # Миграция с прошлой версии: тип запроса (create — новая база, overwrite — перезапись защищённой) и kick
            cols = {r[1] for r in db.execute("PRAGMA table_info(requests)")}
            if "kind" not in cols:
                db.execute("ALTER TABLE requests ADD COLUMN kind TEXT NOT NULL DEFAULT 'create'")
            if "kick" not in cols:
                db.execute("ALTER TABLE requests ADD COLUMN kick INTEGER NOT NULL DEFAULT 0")
            if "checksum" not in cols:
                db.execute("ALTER TABLE requests ADD COLUMN checksum INTEGER NOT NULL DEFAULT 1")
            # Миграция: доступ к базам делится на «создание копий» (backup_dbs) и «источники восстановления» (source_dbs).
            # Раньше этого не было (или был один общий список visible_dbs); чтобы ничего не сломалось, оба новых списка
            # заполняются из общего списка, а при его отсутствии — из баз, разрешённых для восстановления.
            for table in ("users", "groups"):
                cols = {r[1] for r in db.execute("PRAGMA table_info(%s)" % table)}
                if "backup_dbs" not in cols:
                    db.execute("ALTER TABLE %s ADD COLUMN backup_dbs TEXT NOT NULL DEFAULT '[]'" % table)
                    db.execute("ALTER TABLE %s ADD COLUMN source_dbs TEXT NOT NULL DEFAULT '[]'" % table)
                    old = "visible_dbs" if "visible_dbs" in cols else "allowed_dbs"
                    db.execute("UPDATE %s SET backup_dbs = %s, source_dbs = %s" % (table, old, old))
            db.commit()
            _ready = True
    return db


def _jl(text):
    try:
        v = json.loads(text)
        return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []
    except ValueError:
        return []


# ---------- пользователи ----------
def upsert_user(name, display, source, role, dn):
    """Запоминает пользователя при входе. Возвращает True, если он здесь впервые."""
    k, now = key(name), history._now()
    with history.lock:
        db = _db()
        exists = db.execute("SELECT 1 FROM users WHERE name=?", (k,)).fetchone()
        if exists:
            db.execute("UPDATE users SET display=?, source=?, role=?, dn=?, last_login=? WHERE name=?",
                       (display, source, role, dn, now, k))
        else:
            db.execute("INSERT INTO users (name, display, source, role, dn, first_login, last_login) "
                       "VALUES (?,?,?,?,?,?,?)", (k, display, source, role, dn, now, now))
        db.commit()
    return not exists


def list_users():
    with history.lock:
        db = _db()
        rows = db.execute("SELECT name, display, source, role, first_login, last_login, allowed_dbs, backup_dbs, source_dbs "
                          "FROM users ORDER BY name").fetchall()
        groups = {}
        for u, g in db.execute("SELECT username, group_id FROM group_members ORDER BY group_id"):
            groups.setdefault(u, []).append(g)
    return [{"name": r[0], "display": r[1], "source": r[2], "role": r[3], "first_login": r[4],
             "last_login": r[5], "allowed_dbs": _jl(r[6]), "backup_dbs": _jl(r[7]), "source_dbs": _jl(r[8]), "groups": groups.get(r[0], [])} for r in rows]


def user_exists(name):
    with history.lock:
        return _db().execute("SELECT 1 FROM users WHERE name=?", (key(name),)).fetchone() is not None


def set_user(name, allowed_dbs, group_ids, backup_dbs=None, source_dbs=None):
    k = key(name)
    with history.lock:
        db = _db()
        if not db.execute("SELECT 1 FROM users WHERE name=?", (k,)).fetchone():
            return False
        known = {r[0] for r in db.execute("SELECT id FROM groups")}
        if any(g not in known for g in group_ids):
            raise ValueError("Группа не найдена")
        db.execute("UPDATE users SET allowed_dbs=? WHERE name=?", (json.dumps(allowed_dbs, ensure_ascii=False), k))
        for col, val in (("backup_dbs", backup_dbs), ("source_dbs", source_dbs)):
            if val is not None:
                db.execute("UPDATE users SET %s=? WHERE name=?" % col, (json.dumps(val, ensure_ascii=False), k))
        db.execute("DELETE FROM group_members WHERE username=?", (k,))
        db.executemany("INSERT INTO group_members (group_id, username) VALUES (?,?)", [(g, k) for g in set(group_ids)])
        db.commit()
    return True


def delete_user(name):
    k = key(name)
    with history.lock:
        db = _db()
        db.execute("DELETE FROM group_members WHERE username=?", (k,))
        n = db.execute("DELETE FROM users WHERE name=?", (k,)).rowcount
        db.commit()
    return n > 0


# ---------- группы ----------
def list_groups():
    with history.lock:
        db = _db()
        rows = db.execute("SELECT id, name, description, approver, allowed_dbs, backup_dbs, source_dbs FROM groups ORDER BY name").fetchall()
        members = {}
        for g, u in db.execute("SELECT group_id, username FROM group_members ORDER BY username"):
            members.setdefault(g, []).append(u)
    return [{"id": r[0], "name": r[1], "description": r[2], "approver": bool(r[3]),
             "allowed_dbs": _jl(r[4]), "backup_dbs": _jl(r[5]), "source_dbs": _jl(r[6]), "members": members.get(r[0], [])} for r in rows]


def _check_members(db, members):
    out = []
    for m in members:
        k = key(m)
        if not db.execute("SELECT 1 FROM users WHERE name=?", (k,)).fetchone():
            raise ValueError("Пользователь «%s» ещё не входил в систему" % m)
        if k not in out:
            out.append(k)
    return out


def save_group(gid, name, description, approver, allowed_dbs, members, backup_dbs=None, source_dbs=None):
    """gid=None — создать. Возвращает id группы."""
    with history.lock:
        db = _db()
        members = _check_members(db, members)
        try:
            if gid is None:
                gid = db.execute("INSERT INTO groups (name, description, approver, allowed_dbs, backup_dbs, source_dbs) "
                                 "VALUES (?,?,?,?,?,?)",
                                 (name, description, int(approver), json.dumps(allowed_dbs, ensure_ascii=False),
                                  json.dumps(backup_dbs or [], ensure_ascii=False),
                                  json.dumps(source_dbs or [], ensure_ascii=False))).lastrowid
            else:
                if not db.execute("SELECT 1 FROM groups WHERE id=?", (gid,)).fetchone():
                    return None
                db.execute("UPDATE groups SET name=?, description=?, approver=?, allowed_dbs=? WHERE id=?",
                           (name, description, int(approver), json.dumps(allowed_dbs, ensure_ascii=False), gid))
                for col, val in (("backup_dbs", backup_dbs), ("source_dbs", source_dbs)):
                    if val is not None:
                        db.execute("UPDATE groups SET %s=? WHERE id=?" % col, (json.dumps(val, ensure_ascii=False), gid))
        except sqlite3.IntegrityError:
            db.rollback()
            raise ValueError("Группа с таким названием уже есть")
        db.execute("DELETE FROM group_members WHERE group_id=?", (gid,))
        db.executemany("INSERT INTO group_members (group_id, username) VALUES (?,?)", [(gid, m) for m in members])
        db.commit()
    return gid


def delete_group(gid):
    with history.lock:
        db = _db()
        db.execute("DELETE FROM group_members WHERE group_id=?", (gid,))
        n = db.execute("DELETE FROM groups WHERE id=?", (gid,)).rowcount
        db.commit()
    return n > 0


def group_name(gid):
    with history.lock:
        r = _db().execute("SELECT name FROM groups WHERE id=?", (gid,)).fetchone()
    return r[0] if r else ""


# ---------- права ----------
def allowed_dbs(name):
    """Базы, в которые пользователю разрешено восстанавливать: личные + из всех его групп."""
    k = key(name)
    out = set()
    with history.lock:
        db = _db()
        for (txt,) in db.execute("SELECT allowed_dbs FROM users WHERE name=?", (k,)):
            out.update(_jl(txt))
        for (txt,) in db.execute("SELECT g.allowed_dbs FROM groups g JOIN group_members m ON m.group_id=g.id "
                                 "WHERE m.username=?", (k,)):
            out.update(_jl(txt))
    return out


def scope_dbs(name, kind):
    """Базы по виду доступа: "backup" — где можно создавать копии, "source" — чьи копии можно использовать как
    источник восстановления, "restore" — куда можно восстанавливать. Личные + из всех групп пользователя."""
    col = {"backup": "backup_dbs", "source": "source_dbs", "restore": "allowed_dbs"}[kind]
    k = key(name)
    out = set()
    with history.lock:
        db = _db()
        for (txt,) in db.execute("SELECT %s FROM users WHERE name=?" % col, (k,)):
            out.update(_jl(txt))
        for (txt,) in db.execute("SELECT g.%s FROM groups g JOIN group_members m ON m.group_id=g.id "
                                 "WHERE m.username=?" % col, (k,)):
            out.update(_jl(txt))
    return out


def is_approver(name):
    with history.lock:
        r = _db().execute("SELECT 1 FROM groups g JOIN group_members m ON m.group_id=g.id "
                          "WHERE g.approver=1 AND m.username=? LIMIT 1", (key(name),)).fetchone()
    return r is not None


# ---------- запросы на подтверждение ----------
REQ_COLS = ("id", "ts", "requester", "requester_name", "requester_source", "requester_role", "path",
            "source_db", "target", "status", "decided_by", "decided_ts", "comment", "job_id", "kind", "kick", "checksum")


def create_request(user, path, source_db, target, kind="create", kick=False, checksum=True):
    """kind: create — новая база; overwrite — перезапись защищённой базы (подтверждают только администраторы)."""
    with history.lock:
        db = _db()
        rid = db.execute(
            "INSERT INTO requests (ts, requester, requester_name, requester_source, requester_role, path, source_db, "
            "target, kind, kick, checksum) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (history._now(), key(user["name"]), user["name"], user.get("source", ""), user.get("role", ""),
             path, source_db, target, kind, int(kick), int(checksum))).lastrowid
        db.commit()
    return rid


def has_pending(target):
    with history.lock:
        r = _db().execute("SELECT 1 FROM requests WHERE status='pending' AND lower(target)=lower(?)",
                          (target,)).fetchone()
    return r is not None


def get_request(rid):
    with history.lock:
        r = _db().execute("SELECT %s FROM requests WHERE id=?" % ",".join(REQ_COLS), (rid,)).fetchone()
    return dict(zip(REQ_COLS, r)) if r else None


def list_requests(requester=None, limit=100):
    """requester=None — все запросы. К каждому добавляется статус и результат задачи восстановления."""
    sql = ("SELECT %s, h.status, h.details FROM requests r LEFT JOIN history h ON h.id = r.job_id"
           % ",".join("r." + c for c in REQ_COLS))
    args = []
    if requester is not None:
        sql += " WHERE r.requester = ?"
        args.append(requester)
    sql += " ORDER BY r.id DESC LIMIT ?"
    with history.lock:
        rows = _db().execute(sql, args + [limit]).fetchall()
    out = []
    for r in rows:
        d = dict(zip(REQ_COLS, r[:len(REQ_COLS)]))
        d["job_status"], d["job_details"] = r[-2], r[-1]
        out.append(d)
    return out


def pending_count(requester=None):
    sql, args = "SELECT COUNT(*) FROM requests WHERE status='pending'", []
    if requester is not None:
        sql += " AND requester=?"
        args.append(requester)
    with history.lock:
        return _db().execute(sql, args).fetchone()[0]


def decide(rid, status, by, comment=""):
    """Атомарно переводит запрос из pending в новый статус. False — запрос уже обработан."""
    with history.lock:
        db = _db()
        n = db.execute("UPDATE requests SET status=?, decided_by=?, decided_ts=?, comment=? "
                       "WHERE id=? AND status='pending'", (status, by, history._now(), comment[:500], rid)).rowcount
        db.commit()
    return n == 1


def reopen(rid):
    with history.lock:
        db = _db()
        db.execute("UPDATE requests SET status='pending', decided_by='', decided_ts=NULL, comment='' "
                   "WHERE id=? AND status='approved'", (rid,))
        db.commit()


def set_job(rid, job_id):
    with history.lock:
        db = _db()
        db.execute("UPDATE requests SET job_id=? WHERE id=?", (job_id, rid))
        db.commit()


# ---------- защищённые базы ----------
def protected_dbs():
    with history.lock:
        return {r[0] for r in _db().execute("SELECT name FROM protected_dbs")}


def is_protected(name):
    return name in protected_dbs()


def set_protected(names):
    with history.lock:
        db = _db()
        db.execute("DELETE FROM protected_dbs")
        db.executemany("INSERT INTO protected_dbs (name) VALUES (?)", [(n,) for n in names])
        db.commit()
