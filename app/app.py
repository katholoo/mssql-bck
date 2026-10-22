from flask import Flask, jsonify, request, session
import datetime
import hmac
import logging
import re
import os
import secrets
import threading
import time

import access
import config
import history
import ldap_auth
import mssql_ops
import notify
import tls

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("backup")

# ---------- Роли ----------
ROLE_PERMS = {
    "viewer": {"view"},                                   # просмотр
    "operator": {"view", "backup", "restore"},            # создание и восстановление копий
    "full": {"view", "backup", "restore", "settings"},    # полный доступ
}
ROLE_LABELS = {"viewer": "Просмотр", "operator": "Копии и восстановление", "full": "Полный доступ"}

ADMIN_USER = os.environ.get("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")

if not ADMIN_PASSWORD:
    log.warning("ADMIN_PASSWORD не задан: вход локального администратора отключён")


def _secret_key():
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    os.makedirs(config.DATA_DIR, exist_ok=True)
    path = os.path.join(config.DATA_DIR, "secret.key")
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


from flask.sessions import SecureCookieSessionInterface  # noqa: E402


class _SessionInterface(SecureCookieSessionInterface):
    """Cookie сессии получает флаг Secure, если страница открыта по HTTPS (nginx передаёт X-Forwarded-Proto),
    либо принудительно задано COOKIE_SECURE. Так HTTPS можно включить из веб-интерфейса без правки настроек."""
    def get_cookie_secure(self, app):
        return COOKIE_SECURE or request.headers.get("X-Forwarded-Proto", "").lower() == "https"


app = Flask(__name__, static_folder=None)
app.session_interface = _SessionInterface()
app.config.update(
    SECRET_KEY=_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(hours=12),
)
history.startup()

# Права на эндпоинты. Всё, чего здесь нет, запрещено.
PUBLIC = {"health", "login", "logout", "me"}
PERMS = {
    "info": "view", "databases": "view", "backups": "settings",     # список копий — только администратору
    "history_list": "settings", "history_item": "view", "queue_list": "view", "queue_recent": "view", "queue_cancel": "view",
    "restore_sources": "restore", "restore_copies": "restore",
    "backup": "backup", "restore": "restore", "restore_targets": "restore", "request_cancel": "restore",
    "requests_list": "requests", "request_approve": "approve", "request_reject": "approve",
    "access_users": "settings", "access_user_put": "settings", "access_user_delete": "settings",
    "access_groups": "settings", "access_group_create": "settings", "access_group_update": "settings",
    "access_group_delete": "settings", "access_protected_get": "settings", "access_protected_put": "settings",
    "get_ldap": "settings", "put_ldap": "settings", "test_ldap": "settings",
    "tls_get": "settings", "tls_csr_create": "settings", "tls_csr_download": "settings", "tls_csr_delete": "settings",
    "tls_install": "settings",
    "get_notify": "settings", "put_notify": "settings", "test_notify": "settings",
    "get_storage": "settings", "put_storage": "settings", "test_storage": "settings",
}


def perms_for(user):
    """Права пользователя: роль + право подтверждать (полный доступ или внутренняя группа-подтверждающий).
    Считается при каждом запросе, поэтому изменения в группах действуют сразу."""
    perms = set(ROLE_PERMS.get(user.get("role"), set()))
    if user.get("role") == "full" or access.is_approver(user.get("name")):
        perms.add("approve")
    if perms & {"restore", "approve"}:
        perms.add("requests")
    return perms


def client_ip():
    return request.headers.get("X-Real-IP") or request.remote_addr or "?"


def actor():
    return session.get("user") or {}


def log_event(action, target="", status="ok", details="", user=None):
    return history.add(user or actor(), action, target, status, details, client_ip())


@app.before_request
def guard():
    # Простая защита от CSRF: кастомный заголовок нельзя отправить с чужой страницы без CORS
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("X-Requested-With") != "fetch":
        return jsonify(error="Запрещено"), 403
    ep = request.endpoint
    if ep is None or ep in PUBLIC:
        return None
    user = session.get("user")
    if not user:
        return jsonify(error="Требуется вход"), 401
    perm = PERMS.get(ep)
    if perm is None or perm not in perms_for(user):
        return jsonify(error="Недостаточно прав"), 403
    return None


# ---------- Вход ----------
_fails = {}
_fails_lock = threading.Lock()


def too_many_fails(ip):
    now = time.time()
    with _fails_lock:
        recent = [t for t in _fails.get(ip, []) if now - t < 300]
        _fails[ip] = recent
        return len(recent) >= 10


def register_fail(ip):
    with _fails_lock:
        _fails.setdefault(ip, []).append(time.time())


def session_view(user):
    role = user["role"]
    return {"name": user["name"], "display": user["display"], "source": user["source"], "role": role,
            "role_label": ROLE_LABELS[role], "perms": sorted(perms_for(user))}


@app.post("/auth/login")
def login():
    ip = client_ip()
    if too_many_fails(ip):
        return jsonify(error="Слишком много попыток, подождите несколько минут"), 429

    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    password = str(data.get("password", ""))

    user, reason = None, "неверный логин или пароль"
    if username and password:
        if username == ADMIN_USER:
            # Имя локального администратора проверяется только локально
            if ADMIN_PASSWORD and hmac.compare_digest(password.encode(), ADMIN_PASSWORD.encode()):
                user = {"name": username, "display": username, "source": "local", "role": "full"}
        else:
            cfg = config.load("ldap")
            if cfg["enabled"]:
                try:
                    user = ldap_auth.authenticate(cfg, username, password)
                except ldap_auth.AuthError as e:
                    reason = str(e)
                except Exception:
                    log.exception("LDAP: ошибка при входе %r", username)
                    reason = "ошибка LDAP"
            else:
                reason = "LDAP-вход выключен"

    if not user:
        register_fail(ip)
        log_event("login_failed", status="error", details=reason,
                  user={"name": username or "?", "source": "", "role": ""})
        time.sleep(1)
        return jsonify(error="Неверный логин или пароль"), 401

    session.clear()
    session["user"] = user
    session.permanent = True
    if user["source"] == "ldap" and access.upsert_user(user["name"], user["display"], "ldap", user["role"], user.get("dn", "")):
        log_event("user_added", details="добавлен при первом входе из LDAP", user=user)
    log_event("login", details="источник: " + user["source"], user=user)
    return jsonify(user=session_view(user))


@app.post("/auth/logout")
def logout():
    if session.get("user"):
        log_event("logout")
    session.clear()
    return jsonify(ok=True)


@app.get("/auth/me")
def me():
    user = session.get("user")
    return jsonify(authenticated=bool(user), user=session_view(user) if user else None)


def _version():
    try:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION"), encoding="utf-8") as f:
            return f.read().strip() or "?"
    except OSError:
        return "?"


VERSION = _version()


@app.get("/health")
def health():
    return jsonify(ok=True, version=VERSION)


# ---------- Очередь задач (копия / восстановление) ----------
# Задачи выполняет один рабочий поток строго по очереди: две операции на SQL Server одновременно не идут.
# Задача — запись истории со статусом queued → running → ok / error (или cancelled, пока не началась).
_exec_lock = threading.Lock()     # занят, пока выполняется задача или проверка хранилища
_wake = threading.Event()


def enqueue(action, target, params, details="", user=None, ip=None, keep=False):
    """Ставит задачу в очередь от имени user (по умолчанию — текущий; при подтверждении запроса — автор запроса).
    keep — дописать итог к details, а не заменять (нужно, чтобы не потерять «запрос №…, подтвердил …»)."""
    hid = history.enqueue(dict(user or actor()), action, target, {**params, "keep": keep}, details, ip or client_ip())
    _wake.set()
    return hid, history.position(hid)


def _run_job(job):
    p, st = job["params"], config.load("storage")        # настройки хранилища читаются при выполнении
    if job["action"] == "backup":
        return mssql_ops.run_backup(st, p["database"])
    return mssql_ops.run_restore(st, p["path"], p["source"], p["target"], bool(p.get("kick")), bool(p.get("create")))


def _worker():
    while True:
        try:
            job = None
            with _exec_lock:
                _wake.clear()
                job = history.claim_next()
                if job:
                    keep, details = job["params"].get("keep"), job["details"]
                    try:
                        result = _run_job(job)
                        status = "ok"
                        history.finish(job["id"], "ok", "%s; %s" % (details, result) if keep and details else result)
                    except Exception as e:
                        log.exception("%s %s", job["action"], job["target"])
                        result, status = mssql_ops.err_text(e), "error"
                        history.finish(job["id"], "error", "%s; %s" % (details, result) if keep and details else result)
                    notify.job_finished(job, status, result)
            if job is None:
                _wake.wait(5)
        except Exception:
            log.exception("Сбой рабочего потока очереди")
            time.sleep(2)


threading.Thread(target=_worker, daemon=True, name="queue-worker").start()

BUSY_MSG = "Сейчас выполняется проверка или операция, повторите чуть позже"


_PATH_RE = re.compile(r"s3://[^\s;,]+|\\\\[^\s;,]+|[A-Za-z]:\\[^\s;,]+|(?<![\w:/.])/[^\s;,]+")


def short_paths(text):
    """Сокращает пути к файлам и хранилищу до «…/последняя_часть» (для пользователей без полного доступа)."""
    def cut(m):
        tail = re.split(r"[\\/]", m.group(0).rstrip("\\/"))[-1]
        return "…/" + tail if tail else "…"
    return _PATH_RE.sub(cut, str(text or ""))


def _job_view(r, user, position=None):
    mine = access.key(r["username"]) == access.key(user["name"])
    full = user.get("role") == "full"
    return {"id": r["id"], "ts": r["ts"], "finished": r["finished"], "username": r["username"], "source": r["source"],
            "action": r["action"], "target": r["target"], "status": r["status"],
            "details": r["details"] if full else short_paths(r["details"]),
            "position": position, "mine": mine,
            "can_cancel": r["status"] == "queued" and (mine or user.get("role") == "full")}


@app.get("/queue")
def queue_list():
    """Очередь всех пользователей: активные (выполняется + ждут). Завершённые: администратору все, остальным — свои."""
    user = actor()
    full = user.get("role") == "full"
    active, _ = history.queue_snapshot(0)
    done, _ = history.recent_jobs(20, own=None if full else access.key(user["name"]))
    return jsonify(items=[_job_view(r, user, i) for i, r in enumerate(active, 1)],
                   recent=[_job_view(r, user) for r in done])


def _iso_arg(name):
    v = request.args.get(name, "")
    if v and not re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$", v):
        raise ValueError("Некорректная дата")
    return v


@app.get("/queue/recent")
def queue_recent():
    """Недавно завершённые задачи с фильтрами по столбцам. Администратор видит задачи всех, остальные — только свои,
    а пути к файлам в результате показываются в сокращённом виде."""
    user = actor()
    full = user.get("role") == "full"
    try:
        limit = min(max(int(request.args.get("limit", 50)), 1), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
        date_from, date_to = _iso_arg("from"), _iso_arg("to")
    except ValueError:
        return jsonify(error="Некорректные параметры"), 400
    text = request.args.get("text", "").strip()
    py = None if full or not text else (lambda d: text.lower() in short_paths(d).lower())
    items, more = history.recent_jobs(
        limit, offset, request.args.get("action", ""), request.args.get("status", ""),
        request.args.get("user", "").strip() if full else "", request.args.get("target", "").strip(), text,
        date_from, date_to, own=None if full else access.key(user["name"]), python_text=py)
    return jsonify(items=[_job_view(r, user) for r in items], has_more=more)


@app.post("/queue/<int:hid>/cancel")
def queue_cancel(hid):
    user = actor()
    row = history.get(hid)
    if not row or row["action"] not in history.JOB_ACTIONS:
        return jsonify(error="Задача не найдена"), 404
    if access.key(row["username"]) != access.key(user["name"]) and user.get("role") != "full":
        return jsonify(error="Снять с очереди может автор задачи или администратор"), 403
    if not history.cancel_queued(hid):
        return jsonify(error="Задача уже выполняется или завершена"), 409
    log_event("queue_cancel", row["target"], details="задача №%d от %s" % (hid, row["username"]))
    return jsonify(ok=True)


# ---------- Данные ----------
@app.get("/info")
def info():
    """Хранилище и адрес SQL Server — только администратору (остальным место хранения копий не показывается)."""
    if actor().get("role") != "full":
        return jsonify(error="Недостаточно прав"), 403
    st = config.load("storage")
    return jsonify(storage_type=st["type"], storage=mssql_ops.storage_label(st),
                   mssql="%s:%s" % (mssql_ops.HOST, mssql_ops.PORT))


def scope(user, kind):
    """None — без ограничений (полный доступ); иначе множество баз для вида доступа backup / source / restore."""
    return None if user.get("role") == "full" else access.scope_dbs(user.get("name"), kind)


def can(user, kind, db):
    s = scope(user, kind)
    return s is None or db in s


@app.get("/databases")
def databases():
    user = actor()
    try:
        with mssql_ops.connect() as conn:
            dbs = mssql_ops.list_databases(conn)
        # ?for=backup — базы для создания копий; без параметра — все базы, с которыми у пользователя есть хоть какой-то доступ
        kind = request.args.get("for")
        if kind == "backup":
            vis = scope(user, "backup")
        else:
            vis = None if user.get("role") == "full" else (
                access.scope_dbs(user["name"], "backup") | access.scope_dbs(user["name"], "source")
                | access.scope_dbs(user["name"], "restore"))
        return jsonify(databases=dbs if vis is None else [d for d in dbs if d in vis])
    except Exception as e:
        return jsonify(error=mssql_ops.err_text(e)), 502


@app.get("/backups")
def backups():
    """Сделанные копии постранично: ?limit=10|50|100|500 (по умолчанию 50) и ?offset=."""
    try:
        limit = int(request.args.get("limit", 50))
        offset = int(request.args.get("offset", 0))
    except ValueError:
        return jsonify(error="Некорректные параметры"), 400
    if limit not in (10, 50, 100, 500) or offset < 0:
        return jsonify(error="Размер страницы — 10, 50, 100 или 500"), 400
    try:
        with mssql_ops.connect() as conn:
            rows, total = mssql_ops.backups_page(conn, limit, offset)
        return jsonify(backups=rows, total=total, limit=limit, offset=offset)
    except Exception as e:
        return jsonify(error=mssql_ops.err_text(e)), 502


@app.post("/backup")
def backup():
    db = (request.get_json(silent=True) or {}).get("database")
    if not isinstance(db, str) or not db:
        return jsonify(error="Не указана база"), 400
    if not can(actor(), "backup", db):
        return jsonify(error="Создавать копии базы «%s» вам не разрешено" % db), 403
    hid, pos = enqueue("backup", db, {"database": db}, "в " + mssql_ops.storage_label(config.load("storage")))
    return jsonify(id=hid, position=pos), 202


def user_targets(user, conn):
    """Существующие базы, в которые этому пользователю можно восстанавливать.
    Полный доступ — любые несистемные; остальным — только отмеченные лично или через группы
    (по умолчанию ничего не отмечено, список пуст)."""
    existing = [d for d in mssql_ops.list_databases(conn) if d not in mssql_ops.SYSTEM_DBS]
    if user.get("role") == "full":
        return existing
    allowed = access.allowed_dbs(user.get("name"))
    return [d for d in existing if d in allowed]


@app.get("/restore/targets")
def restore_targets():
    user = actor()
    try:
        with mssql_ops.connect() as conn:
            dbs = user_targets(user, conn)
    except Exception as e:
        return jsonify(error=mssql_ops.err_text(e)), 502
    full = user.get("role") == "full"
    protected = [] if full else sorted(access.protected_dbs() & set(dbs))
    return jsonify(databases=dbs, needs_approval=not full, protected=protected)


@app.get("/restore/sources")
def restore_sources():
    """Базы, из копий которых можно восстанавливать (только имя и дата последней копии, без путей)."""
    try:
        with mssql_ops.connect() as conn:
            src = mssql_ops.sources(conn)
        vis = scope(actor(), "source")
        return jsonify(sources=src if vis is None else [x for x in src if x["database"] in vis])
    except Exception as e:
        return jsonify(error=mssql_ops.err_text(e)), 502


@app.get("/restore/copies")
def restore_copies():
    """Все копии выбранной базы для списка в форме восстановления: id, дата, размер (без путей к файлам)."""
    db = request.args.get("database", "")
    if not db:
        return jsonify(error="Не указана база"), 400
    if not can(actor(), "source", db):
        return jsonify(error="Копии базы «%s» вам недоступны" % db), 403
    try:
        with mssql_ops.connect() as conn:
            return jsonify(copies=mssql_ops.copies(conn, db))
    except Exception as e:
        return jsonify(error=mssql_ops.err_text(e)), 502


@app.post("/restore")
def restore():
    """Ставит восстановление в очередь. Источник: копия `copy` (id из /restore/copies) базы `database`,
    а если копия не указана — последняя копия `database`. Путь к файлу (`path`) допустим только администратору."""
    data = request.get_json(silent=True) or {}
    path, src_db, copy_id = data.get("path"), data.get("database"), data.get("copy")
    path = path if isinstance(path, str) and path else None
    src_db = src_db if isinstance(src_db, str) and src_db else None
    if copy_id is not None and (not isinstance(copy_id, int) or isinstance(copy_id, bool)):
        return jsonify(error="Некорректный номер копии"), 400
    target = str(data.get("target") or "").strip()
    new = bool(data.get("new"))
    user = actor()
    if not target or not (path or src_db or copy_id is not None):
        return jsonify(error="Не указаны база для восстановления или целевая база"), 400
    if path and user.get("role") != "full":
        return jsonify(error="Выбрать файл копии по пути может только администратор"), 403
    try:
        with mssql_ops.connect() as conn:
            if path:
                found = mssql_ops.find_backup(conn, path)
            elif copy_id is not None:
                found = mssql_ops.find_backup_id(conn, copy_id)
            else:
                found = mssql_ops.latest_backup(conn, src_db)
            all_dbs = mssql_ops.list_databases(conn)
            targets = user_targets(user, conn)
    except Exception as e:
        return jsonify(error=mssql_ops.err_text(e)), 502
    if not found:
        return jsonify(error="Для базы «%s» нет копий" % src_db if not (path or copy_id is not None)
                       else "Копия не найдена в журнале SQL Server"), 404
    if not can(user, "source", found["database"]):
        return jsonify(error="Копии базы «%s» вам недоступны" % found["database"]), 403
    if copy_id is not None and src_db and found["database"] != src_db:
        return jsonify(error="Выбранная копия относится к другой базе"), 400
    path, source = found["path"], found["database"]

    if new:
        if not mssql_ops.valid_db_name(target):
            return jsonify(error="Некорректное имя базы (1–128 символов, без управляющих символов)"), 400
        if target in mssql_ops.SYSTEM_DBS or target.lower() in {d.lower() for d in all_dbs}:
            return jsonify(error="База «%s» уже существует" % target), 400
        if user.get("role") != "full":
            # Создание новой базы — по запросу, который подтверждает внутренняя группа
            if access.has_pending(target):
                return jsonify(error="Запрос на создание базы «%s» уже ожидает подтверждения" % target), 409
            rid = access.create_request(user, path, source, target)
            log_event("request_create", "%s -> %s" % (source, target), details="запрос №%d, копия %s" % (rid, path))
            return jsonify(request=rid, needs_approval=True), 202
        create = True
    else:
        if target not in targets:
            return jsonify(error="Нет права восстанавливать в базу «%s»" % target), 403
        if data.get("confirm") != target:
            return jsonify(error="Для перезаписи базы подтвердите её имя"), 400
        create = False
        if user.get("role") != "full" and access.is_protected(target):
            # Защищённая база: перезапись только после подтверждения администратором
            if access.has_pending(target):
                return jsonify(error="Запрос на перезапись базы «%s» уже ожидает подтверждения" % target), 409
            rid = access.create_request(user, path, source, target, "overwrite", bool(data.get("kick_users")))
            log_event("request_create", "%s -> %s" % (source, target),
                      details="запрос №%d на перезапись защищённой базы, копия %s" % (rid, path))
            return jsonify(request=rid, needs_approval=True, kind="overwrite"), 202

    kick = bool(data.get("kick_users")) and not create
    hid, pos = enqueue("restore", "%s -> %s" % (source, target),
                       {"path": path, "source": source, "target": target, "kick": kick, "create": create}, path)
    return jsonify(id=hid, position=pos), 202


# ---------- Запросы на создание баз ----------
def _request_view(r, me_key, perms, role):
    pending = r["status"] == "pending"
    mine = r["requester"] == me_key
    admin_only = r["kind"] == "overwrite"       # перезапись защищённой базы подтверждают только администраторы
    return {**r, "mine": mine,
            "can_decide": pending and "approve" in perms and not mine and (role == "full" or not admin_only),
            "can_cancel": pending and (mine or "settings" in perms)}


@app.get("/requests")
def requests_list():
    user = actor()
    perms = perms_for(user)
    own = None if "approve" in perms else access.key(user["name"])
    items = [_request_view(r, access.key(user["name"]), perms, user.get("role")) for r in access.list_requests(own, 100)]
    # Счётчик: подтверждающему — запросы, которые он может решить; остальным — их собственные ожидающие
    pending = sum(1 for i in items if i["can_decide"]) if own is None else access.pending_count(own)
    return jsonify(items=items, pending=pending)


@app.post("/requests/<int:rid>/approve")
def request_approve(rid):
    user = actor()
    req = access.get_request(rid)
    if not req:
        return jsonify(error="Запрос не найден"), 404
    if req["status"] != "pending":
        return jsonify(error="Запрос уже обработан"), 409
    if req["requester"] == access.key(user["name"]):
        return jsonify(error="Нельзя подтверждать собственный запрос — его должен подтвердить другой человек"), 403
    overwrite = req["kind"] == "overwrite"
    if overwrite and user.get("role") != "full":
        return jsonify(error="Перезапись защищённой базы может подтвердить только администратор (полный доступ)"), 403
    try:
        with mssql_ops.connect() as conn:
            found = mssql_ops.find_backup(conn, req["path"])
            all_dbs = mssql_ops.list_databases(conn)
    except Exception as e:
        return jsonify(error=mssql_ops.err_text(e)), 502
    if not found:
        return jsonify(error="Копия больше не найдена в журнале SQL Server"), 409
    exists = req["target"].lower() in {d.lower() for d in all_dbs}
    if overwrite and not exists:
        return jsonify(error="База «%s» больше не существует" % req["target"]), 409
    if not overwrite and exists:
        return jsonify(error="База «%s» уже существует" % req["target"]), 409

    comment = str((request.get_json(silent=True) or {}).get("comment") or "")
    if not access.decide(rid, "approved", user["name"], comment):
        return jsonify(error="Запрос уже обработан"), 409
    requester = {"name": req["requester_name"], "source": req["requester_source"], "role": req["requester_role"]}
    src, target, path, kick = req["source_db"], req["target"], req["path"], bool(req["kick"])
    try:
        hid, pos = enqueue("restore", "%s -> %s" % (src, target),
                           {"path": path, "source": src, "target": target, "kick": kick, "create": not overwrite},
                           "запрос №%d от %s, подтвердил %s; %s" % (rid, req["requester_name"], user["name"], path),
                           user=requester, ip=client_ip(), keep=True)
    except Exception:
        access.reopen(rid)
        raise
    access.set_job(rid, hid)
    log_event("request_approve", "%s -> %s" % (src, target), details="запрос №%d от %s" % (rid, req["requester_name"]))
    return jsonify(id=hid, position=pos), 202


@app.post("/requests/<int:rid>/reject")
def request_reject(rid):
    user = actor()
    req = access.get_request(rid)
    if not req:
        return jsonify(error="Запрос не найден"), 404
    if req["kind"] == "overwrite" and user.get("role") != "full":
        return jsonify(error="Запросы на перезапись защищённых баз рассматривает только администратор (полный доступ)"), 403
    comment = str((request.get_json(silent=True) or {}).get("comment") or "")
    if not access.decide(rid, "rejected", user["name"], comment):
        return jsonify(error="Запрос уже обработан"), 409
    log_event("request_reject", "%s -> %s" % (req["source_db"], req["target"]),
              details="запрос №%d от %s%s" % (rid, req["requester_name"], ": " + comment if comment else ""))
    return jsonify(ok=True)


@app.post("/requests/<int:rid>/cancel")
def request_cancel(rid):
    user = actor()
    req = access.get_request(rid)
    if not req:
        return jsonify(error="Запрос не найден"), 404
    if req["requester"] != access.key(user["name"]) and "settings" not in perms_for(user):
        return jsonify(error="Отменить запрос может только его автор"), 403
    if not access.decide(rid, "cancelled", user["name"]):
        return jsonify(error="Запрос уже обработан"), 409
    log_event("request_cancel", "%s -> %s" % (req["source_db"], req["target"]), details="запрос №%d" % rid)
    return jsonify(ok=True)


# ---------- История ----------
@app.get("/history")
def history_list():
    try:
        limit = min(max(int(request.args.get("limit", 100)), 1), 200)
        offset = max(int(request.args.get("offset", 0)), 0)
    except ValueError:
        return jsonify(error="Некорректные параметры"), 400
    items, has_more = history.query(limit, offset, request.args.get("action", ""),
                                    request.args.get("user", ""), request.args.get("status", ""))
    return jsonify(items=items, has_more=has_more)


@app.get("/history/<int:hid>")
def history_item(hid):
    """Запись истории. Полный доступ — любая; остальные — только свои задачи (копия/восстановление; нужно, чтобы
    следить за ходом своей задачи), с сокращёнными путями."""
    user = actor()
    row = history.get(hid)
    if not row:
        return jsonify(error="Не найдено"), 404
    if user.get("role") != "full":
        if row["action"] not in history.JOB_ACTIONS or access.key(row["username"]) != access.key(user["name"]):
            return jsonify(error="Не найдено"), 404
        row = {k: row[k] for k in ("id", "ts", "finished", "action", "target", "status")} | {"details": short_paths(row["details"])}
    return jsonify(row)


# ---------- Настройки ----------
@app.get("/settings/ldap")
def get_ldap():
    return jsonify(config.public("ldap", config.load("ldap")))


@app.put("/settings/ldap")
def put_ldap():
    old = config.load("ldap")
    try:
        new = config.build("ldap", request.get_json(silent=True) or {}, old)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    config.save("ldap", new)
    log_event("settings_ldap", details=", ".join(config.changed_keys(old, new)) or "без изменений")
    return jsonify(config.public("ldap", new))


@app.post("/settings/ldap/test")
def test_ldap():
    body = request.get_json(silent=True) or {}
    try:
        cfg = config.build("ldap", body.get("config") or {}, config.load("ldap"), mode="test")
    except ValueError as e:
        return jsonify(ok=False, error=str(e)), 400

    result = {"ok": True}
    try:
        result["connection"] = ldap_auth.test_connection(cfg)
        tu, tp = str(body.get("test_user") or "").strip(), str(body.get("test_password") or "")
        if tu or tp:
            u = ldap_auth.authenticate(cfg, tu, tp)
            result["user"] = "Вход выполнен: %s (%s), роль: %s" % (u["display"], u["dn"], ROLE_LABELS[u["role"]])
    except ldap_auth.AuthError as e:
        result = {"ok": False, "error": str(e)}
    except Exception as e:
        log.exception("LDAP test")
        result = {"ok": False, "error": "Ошибка: %s" % e}
    log_event("settings_test", "ldap", "ok" if result["ok"] else "error",
              result.get("user") or result.get("connection") or result.get("error", ""))
    return jsonify(result)


@app.get("/settings/storage")
def get_storage():
    return jsonify(config.public("storage", config.load("storage")))


@app.put("/settings/storage")
def put_storage():
    old = config.load("storage")
    try:
        new = config.build("storage", request.get_json(silent=True) or {}, old)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    config.save("storage", new)
    log_event("settings_storage", mssql_ops.storage_label(new),
              details=", ".join(config.changed_keys(old, new)) or "без изменений")
    return jsonify(config.public("storage", new))


@app.post("/settings/storage/test")
def test_storage():
    body = request.get_json(silent=True) or {}
    try:
        st = config.build("storage", body.get("config") or {}, config.load("storage"), mode="test")
    except ValueError as e:
        return jsonify(ok=False, error=str(e)), 400
    if not _exec_lock.acquire(blocking=False):            # идёт задача очереди
        return jsonify(ok=False, error=BUSY_MSG), 409
    try:
        path = mssql_ops.test_storage(st)
        result = {"ok": True, "message": "Тестовая копия записана: " + path}
    except Exception as e:
        result = {"ok": False, "error": mssql_ops.err_text(e)}
    finally:
        _exec_lock.release()
    log_event("settings_test", "storage", "ok" if result["ok"] else "error",
              result.get("message") or result.get("error", ""))
    return jsonify(result)


# ---------- HTTPS-сертификат ----------
@app.get("/settings/tls")
def tls_get():
    pend = tls.pending()
    host = (request.headers.get("Host") or "").split(":")[0].strip("[]").lower()
    return jsonify(installed=tls.installed(), pending=pend, apply=tls.apply_status(), waiting=tls.waiting_request(),
                   default_cn=host, secure=request.headers.get("X-Forwarded-Proto", "").lower() == "https")


@app.post("/settings/tls/csr")
def tls_csr_create():
    d = request.get_json(silent=True) or {}
    try:
        res = tls.create_csr(d.get("cn"), d.get("sans"), d.get("org"), d.get("unit"), d.get("country"),
                             d.get("state"), d.get("city"), d.get("key_bits", 2048))
    except tls.TlsError as e:
        return jsonify(error=str(e)), 400
    log_event("settings_tls", res["cn"], details="создан запрос сертификата (CSR): %s, RSA %d" % (res["subject"], res["key_bits"]))
    return jsonify(pending=res), 201


@app.get("/settings/tls/csr")
def tls_csr_download():
    data = tls.csr_pem()
    if data is None:
        return jsonify(error="Запроса нет"), 404
    return app.response_class(data, mimetype="application/pkcs10",
                              headers={"Content-Disposition": 'attachment; filename="mssql-backup.csr"'})


@app.delete("/settings/tls/csr")
def tls_csr_delete():
    tls.cancel_pending()
    log_event("settings_tls", details="запрос сертификата (CSR) отменён, закрытый ключ удалён")
    return jsonify(ok=True)


@app.post("/settings/tls/install")
def tls_install():
    d = request.get_json(silent=True) or {}
    try:
        if d.get("certificate_b64"):
            data = tls.der_from_b64(str(d["certificate_b64"]))
        else:
            data = str(d.get("certificate") or "").encode("utf-8")
        res = tls.validate_and_stage(data, d.get("https_port", 443), d.get("redirect_http", True), actor().get("name", ""))
    except tls.TlsError as e:
        log_event("settings_tls", status="error", details="установка сертификата отклонена: %s" % e)
        return jsonify(error=str(e)), 400
    c = res["certificate"]
    log_event("settings_tls", c["cn"], details="сертификат передан на установку: %s, действует до %s, отпечаток SHA-256 %s"
              % (c["subject"], c["not_after"], c["sha256"]))
    return jsonify(res), 202


@app.get("/settings/notify")
def get_notify():
    return jsonify(config.public("notify", config.load("notify")))


@app.put("/settings/notify")
def put_notify():
    old = config.load("notify")
    try:
        new = config.build("notify", request.get_json(silent=True) or {}, old)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    config.save("notify", new)
    log_event("settings_notify", details=", ".join(k for k in config.changed_keys(old, new)
                                                   if k not in config.SECRET["notify"]) or "без изменений")
    return jsonify(config.public("notify", new))


@app.post("/settings/notify/test")
def test_notify():
    body = request.get_json(silent=True) or {}
    channel = body.get("channel")
    if channel not in ("email", "telegram", "bitrix24", "webhook"):
        return jsonify(ok=False, error="Неизвестный канал"), 400
    try:
        cfg = config.build("notify", body.get("config") or {}, config.load("notify"), mode="test")
        notify.send(cfg, channel, "Проверка уведомлений",
                    "Тестовое сообщение сервиса резервного копирования MSSQL.",
                    {"event": "test"})
        result = {"ok": True, "message": "Тестовое сообщение отправлено"}
    except ValueError as e:
        return jsonify(ok=False, error=str(e)), 400
    except Exception as e:
        result = {"ok": False, "error": "Не удалось отправить: %s" % e}
    log_event("settings_test", "notify:" + channel, "ok" if result["ok"] else "error",
              result.get("message") or result.get("error", ""))
    return jsonify(result)


# ---------- Пользователи и внутренние группы ----------
def _clean_dbs(value):
    if not isinstance(value, list):
        raise ValueError("Список баз должен быть массивом")
    out = []
    for x in value:
        if not isinstance(x, str) or not mssql_ops.valid_db_name(x):
            raise ValueError("Некорректное имя базы в списке")
        if x not in out and x not in mssql_ops.SYSTEM_DBS:
            out.append(x)
    if len(out) > 500:
        raise ValueError("Слишком много баз в списке")
    return out


def _clean_group(data):
    name = str(data.get("name") or "").strip()
    if not 1 <= len(name) <= 64:
        raise ValueError("Название группы — от 1 до 64 символов")
    members = data.get("members") or []
    if not isinstance(members, list) or not all(isinstance(m, str) for m in members):
        raise ValueError("Участники должны быть списком логинов")
    return (name, str(data.get("description") or "").strip()[:300], bool(data.get("approver")),
            _clean_dbs(data.get("allowed_dbs") or []), members,
            _clean_dbs(data["backup_dbs"]) if "backup_dbs" in data else None,
            _clean_dbs(data["source_dbs"]) if "source_dbs" in data else None)


@app.get("/access/users")
def access_users():
    return jsonify(users=access.list_users())


@app.put("/access/users/<name>")
def access_user_put(name):
    data = request.get_json(silent=True) or {}
    try:
        dbs = _clean_dbs(data.get("allowed_dbs") or [])
        bk = _clean_dbs(data["backup_dbs"]) if "backup_dbs" in data else None
        src = _clean_dbs(data["source_dbs"]) if "source_dbs" in data else None
        groups = data.get("groups") or []
        if not isinstance(groups, list) or not all(isinstance(g, int) for g in groups):
            raise ValueError("Группы должны быть списком идентификаторов")
        if not access.set_user(name, dbs, groups, bk, src):
            return jsonify(error="Пользователь не найден"), 404
    except ValueError as e:
        return jsonify(error=str(e)), 400
    log_event("settings_access", "user:" + access.key(name),
              details="копии: %s; источники: %s; восстановление: %d; группы: %s" % (
                  len(bk) if bk is not None else "без изменений", len(src) if src is not None else "без изменений", len(dbs), ", ".join(access.group_name(g) for g in groups) or "нет"))
    return jsonify(ok=True)


@app.delete("/access/users/<name>")
def access_user_delete(name):
    if not access.delete_user(name):
        return jsonify(error="Пользователь не найден"), 404
    log_event("settings_access", "user:" + access.key(name), details="удалён из списка (появится снова при входе)")
    return jsonify(ok=True)


@app.get("/access/groups")
def access_groups():
    return jsonify(groups=access.list_groups())


@app.post("/access/groups")
def access_group_create():
    try:
        name, desc, approver, dbs, members, bk, src = _clean_group(request.get_json(silent=True) or {})
        gid = access.save_group(None, name, desc, approver, dbs, members, bk, src)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    log_event("settings_access", "group:" + name, details="создана; подтверждающая: %s; копии: %d; источники: %d; восстановление: %d; участников: %d"
              % ("да" if approver else "нет", len(bk or []), len(src or []), len(dbs), len(members)))
    return jsonify(id=gid), 201


@app.put("/access/groups/<int:gid>")
def access_group_update(gid):
    try:
        name, desc, approver, dbs, members, bk, src = _clean_group(request.get_json(silent=True) or {})
        if access.save_group(gid, name, desc, approver, dbs, members, bk, src) is None:
            return jsonify(error="Группа не найдена"), 404
    except ValueError as e:
        return jsonify(error=str(e)), 400
    log_event("settings_access", "group:" + name, details="изменена; подтверждающая: %s; копии: %s; источники: %s; восстановление: %d; участников: %d"
              % ("да" if approver else "нет", len(bk) if bk is not None else "без изменений",
                 len(src) if src is not None else "без изменений", len(dbs), len(members)))
    return jsonify(ok=True)


@app.delete("/access/groups/<int:gid>")
def access_group_delete(gid):
    name = access.group_name(gid)
    if not access.delete_group(gid):
        return jsonify(error="Группа не найдена"), 404
    log_event("settings_access", "group:" + name, details="удалена")
    return jsonify(ok=True)


@app.get("/access/protected")
def access_protected_get():
    return jsonify(databases=sorted(access.protected_dbs()))


@app.put("/access/protected")
def access_protected_put():
    try:
        names = _clean_dbs((request.get_json(silent=True) or {}).get("databases") or [])
    except ValueError as e:
        return jsonify(error=str(e)), 400
    old = access.protected_dbs()
    access.set_protected(names)
    log_event("settings_access", "protected", details="защищённые базы: %s" % (", ".join(names) or "нет"))
    return jsonify(databases=sorted(names), changed=sorted(old ^ set(names)))
