"""Операции с SQL Server: список баз, бэкап, восстановление, проверка хранилища.

SQL Server сам пишет и читает .bak (в локальную папку на своём сервере, по UNC-пути
или в S3), поэтому веб-сервису не нужен доступ к файлам.
"""
import datetime
import os
import re

HOST = os.environ.get("MSSQL_HOST", "localhost")
PORT = int(os.environ.get("MSSQL_PORT", "1433"))
USER = os.environ.get("MSSQL_USER", "sa")
PASSWORD = os.environ.get("MSSQL_PASSWORD", "")

SYSTEM_DBS = ("master", "model", "msdb", "tempdb")
TEST_FILE = "mssql_backup_web_write_test.bak"


def connect():
    import pytds  # импорт здесь, чтобы модуль загружался и без драйвера
    # BACKUP/RESTORE нельзя выполнять внутри транзакции -> autocommit; timeout=None — без лимита
    return pytds.connect(dsn=HOST, port=PORT, user=USER, password=PASSWORD,
                         autocommit=True, login_timeout=15, timeout=None)


def err_text(e):
    """Читаемый текст из исключения драйвера."""
    text = ""
    for a in getattr(e, "args", ()):
        if isinstance(a, (bytes, bytearray)):
            text = a.decode("utf-8", "replace")
            break
        if isinstance(a, str) and a:
            text = a
            break
    text = (text or str(e) or e.__class__.__name__).strip()
    return text[:1500]


def qid(name):
    return "[" + name.replace("]", "]]") + "]"


def qlit(value):
    return "N'" + value.replace("'", "''") + "'"


def safe_name(name):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name)


# ---------- хранилище ----------
def s3_base(st):
    """Префикс URL до бакета; он же имя credential в SQL Server."""
    host = st["s3_endpoint"] + ("" if int(st["s3_port"]) == 443 else ":%d" % int(st["s3_port"]))
    if st["s3_virtual_host"]:
        return "s3://%s.%s" % (st["s3_bucket"], host)
    return "s3://%s/%s" % (host, st["s3_bucket"])


def storage_label(st):
    if st["type"] == "s3":
        return "/".join(p for p in (s3_base(st), st["s3_prefix"]) if p)
    return st["smb_path"] if st["type"] == "smb" else st["local_path"]


def build_target(st, db, when=None, filename=None):
    """Возвращает (DISK|URL, полный путь для SQL Server)."""
    fname = filename or "%s_%s.bak" % (safe_name(db), (when or datetime.datetime.now()).strftime("%Y%m%d_%H%M%S"))
    if st["type"] == "s3":
        path = "/".join(p for p in (s3_base(st), st["s3_prefix"], fname) if p)
        if len(path.encode()) > 259:
            raise ValueError("URL бэкапа длиннее 259 байт — сократите префикс или имя бакета")
        return "URL", path
    if st["type"] == "smb":
        return "DISK", st["smb_path"].rstrip("\\") + "\\" + fname
    base = st["local_path"]
    sep = "\\" if ("\\" in base or re.match(r"^[A-Za-z]:", base)) else "/"
    return "DISK", base.rstrip("/\\") + sep + fname


def ensure_s3_credential(cur, st):
    """Создаёт (пересоздаёт) credential с ключами из настроек. Имя = префикс URL."""
    name = s3_base(st)
    cur.execute("IF EXISTS (SELECT 1 FROM sys.credentials WHERE name = %s) DROP CREDENTIAL %s"
                % (qlit(name), qid(name)))
    cur.execute("CREATE CREDENTIAL %s WITH IDENTITY = 'S3 Access Key', SECRET = %s"
                % (qid(name), qlit(st["s3_access_key"] + ":" + st["s3_secret_key"])))


def _backup_sql(db, kind, path, label):
    opts = ["COPY_ONLY", "CHECKSUM", "COMPRESSION", "NAME = " + qlit(label[:128])]
    opts += ["FORMAT", "MAXTRANSFERSIZE = 20971520"] if kind == "URL" else ["INIT"]
    return "BACKUP DATABASE %s TO %s = %s WITH %s" % (qid(db), kind, qlit(path), ", ".join(opts))


# ---------- запросы ----------
def list_databases(conn):
    cur = conn.cursor()
    cur.execute("SELECT name FROM sys.databases WHERE state_desc = 'ONLINE' ORDER BY name")
    return [r[0] for r in cur.fetchall() if r[0] != "tempdb"]


def database_exists(cur, name):
    cur.execute("SELECT 1 FROM sys.databases WHERE name = %s" % qlit(name))
    return cur.fetchone() is not None


BACKUPS_SQL = """
SELECT TOP %d bs.database_name, bs.backup_finish_date, bs.backup_size, bs.compressed_backup_size,
       bmf.physical_device_name, bs.user_name, bs.backup_set_id
FROM msdb.dbo.backupset bs
JOIN msdb.dbo.backupmediafamily bmf ON bmf.media_set_id = bs.media_set_id
WHERE bs.type = 'D' AND bmf.family_sequence_number = 1 AND bmf.device_type IN (2, 9)
  AND bmf.physical_device_name NOT LIKE N'%%%s'
%s
ORDER BY bs.backup_finish_date DESC
"""


def _backups_query(path=None, database=None, backup_id=None, top=300):
    extra = []
    if path:
        extra.append("AND bmf.physical_device_name = %s" % qlit(path))
    if database:
        extra.append("AND bs.database_name = %s" % qlit(database))
    if backup_id is not None:
        extra.append("AND bs.backup_set_id = %d" % int(backup_id))
    return BACKUPS_SQL % (int(top), TEST_FILE, "\n".join(extra))


_BACKUPS_FROM = """
FROM msdb.dbo.backupset bs
JOIN msdb.dbo.backupmediafamily bmf ON bmf.media_set_id = bs.media_set_id
WHERE bs.type = 'D' AND bmf.family_sequence_number = 1 AND bmf.device_type IN (2, 9)
  AND bmf.physical_device_name NOT LIKE N'%%%s'
"""


def backups_page(conn, limit, offset):
    """Страница полных копий из msdb (новые первыми) и общее число копий: (список, всего)."""
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) " + _BACKUPS_FROM % TEST_FILE)
    total = int(cur.fetchone()[0])
    cur.execute("SELECT bs.database_name, bs.backup_finish_date, bs.backup_size, bs.compressed_backup_size, "
                "bmf.physical_device_name, bs.user_name, bs.backup_set_id " + _BACKUPS_FROM % TEST_FILE
                + "ORDER BY bs.backup_finish_date DESC, bs.backup_set_id DESC "
                  "OFFSET %d ROWS FETCH NEXT %d ROWS ONLY" % (int(offset), int(limit)))
    return [_backup_row(r) for r in cur.fetchall()], total


def _backup_row(r):
    finished = r[1]
    return {
        "id": int(r[6]),
        "database": r[0],
        "finished": finished.isoformat(timespec="seconds") if finished else "",
        "size": int(r[2] or 0),
        "compressed_size": int(r[3] or 0),
        "path": r[4],
        "user": r[5] or "",
    }


def list_backups(conn, database=None, top=300):
    """Полные копии из журнала msdb: туда SQL Server пишет все бэкапы, куда бы они ни ушли."""
    cur = conn.cursor()
    cur.execute(_backups_query(database=database, top=top))
    return [_backup_row(r) for r in cur.fetchall()]


def latest_backup(conn, database):
    """Последняя полная копия базы из журнала msdb (None, если копий нет)."""
    rows = list_backups(conn, database=database, top=1)
    return rows[0] if rows else None


def copies(conn, database, top=200):
    """Все копии базы (от новых к старым) без путей к файлам: id, дата, размер."""
    return [{"id": b["id"], "finished": b["finished"], "size": b["compressed_size"] or b["size"]}
            for b in list_backups(conn, database=database, top=top)]


def sources(conn):
    """Базы, у которых есть копии, с датой последней: без путей к файлам."""
    seen, out = set(), []
    for b in list_backups(conn, top=2000):
        if b["database"] not in seen:
            seen.add(b["database"])
            out.append({"database": b["database"], "finished": b["finished"]})
    return sorted(out, key=lambda x: x["database"].lower())


def find_backup_id(conn, backup_id):
    cur = conn.cursor()
    cur.execute(_backups_query(backup_id=backup_id, top=1))
    row = cur.fetchone()
    return _backup_row(row) if row else None


def find_backup(conn, path):
    cur = conn.cursor()
    cur.execute(_backups_query(path))
    row = cur.fetchone()
    return _backup_row(row) if row else None


# ---------- операции ----------
def run_backup(st, db):
    kind, path = build_target(st, db)
    with connect() as conn:
        if db not in list_databases(conn):
            raise ValueError("База не найдена или не в сети")
        cur = conn.cursor()
        if st["type"] == "s3":
            ensure_s3_credential(cur, st)
        cur.execute(_backup_sql(db, kind, path, "mssql-backup-web " + db))
    return path


def valid_db_name(name):
    return (isinstance(name, str) and 1 <= len(name) <= 128 and name == name.strip()
            and not any(ord(c) < 32 for c in name))


def _restore_into_existing(cur, src, source_db, target):
    """Перезапись существующей базы. Для другой базы (не исходной) файлы копии по порядку
    переносятся на файлы целевой базы, поэтому число файлов данных и журнала должно совпадать."""
    if target == source_db:
        return "RESTORE DATABASE %s FROM %s WITH REPLACE, RECOVERY, CHECKSUM" % (qid(target), src)

    cur.execute("RESTORE FILELISTONLY FROM %s" % src)
    backup_files = [(r[0], r[2]) for r in cur.fetchall()]
    cur.execute("SELECT type, physical_name FROM sys.master_files WHERE database_id = DB_ID(%s) ORDER BY file_id"
                % qlit(target))
    target_files = cur.fetchall()
    if any(t not in ("D", "L") for _, t in backup_files) or any(t not in (0, 1) for t, _ in target_files):
        raise ValueError("FILESTREAM и полнотекстовые файлы не поддерживаются при перезаписи другой базы")
    bdata = [n for n, t in backup_files if t == "D"]
    blog = [n for n, t in backup_files if t == "L"]
    tdata = [p for t, p in target_files if t == 0]
    tlog = [p for t, p in target_files if t == 1]
    if len(bdata) != len(tdata) or len(blog) != len(tlog):
        raise ValueError(
            "Структура файлов копии (данные: %d, журнал: %d) не совпадает с базой «%s» (данные: %d, журнал: %d). "
            "Восстановите как новую базу" % (len(bdata), len(blog), target, len(tdata), len(tlog)))
    moves = ["MOVE %s TO %s" % (qlit(n), qlit(p)) for n, p in list(zip(bdata, tdata)) + list(zip(blog, tlog))]
    return "RESTORE DATABASE %s FROM %s WITH %s, REPLACE, RECOVERY, CHECKSUM" % (qid(target), src, ", ".join(moves))


def run_restore(st, path, source_db, target, kick_users=False, create=False):
    """create=False — перезаписать существующую базу target; create=True — создать новую."""
    if target in SYSTEM_DBS:
        raise ValueError("Восстановление системных баз запрещено")
    kind = "URL" if path.lower().startswith("s3://") else "DISK"
    src = "%s = %s" % (kind, qlit(path))
    with connect() as conn:
        cur = conn.cursor()
        if kind == "URL" and st["type"] == "s3":
            ensure_s3_credential(cur, st)
        exists = database_exists(cur, target)

        if not create:
            if not exists:
                raise ValueError("База «%s» не найдена" % target)
            sql = _restore_into_existing(cur, src, source_db, target)
            if kick_users:
                cur.execute("ALTER DATABASE %s SET SINGLE_USER WITH ROLLBACK IMMEDIATE" % qid(target))
            try:
                cur.execute(sql)
            finally:
                if kick_users:
                    try:
                        cur.execute("ALTER DATABASE %s SET MULTI_USER" % qid(target))
                    except Exception:
                        pass
            return "%s -> %s (перезапись)" % (path, target)

        # Новая база: файлы кладём в папки по умолчанию
        if exists:
            raise ValueError("База «%s» уже существует" % target)
        cur.execute("SELECT CAST(SERVERPROPERTY('InstanceDefaultDataPath') AS nvarchar(512)), "
                    "CAST(SERVERPROPERTY('InstanceDefaultLogPath') AS nvarchar(512))")
        data_dir, log_dir = cur.fetchone()
        if not data_dir or not log_dir:
            raise ValueError("Не удалось определить папки данных SQL Server (нужен SQL Server 2012+)")
        cur.execute("RESTORE FILELISTONLY FROM %s" % src)
        moves = []
        for row in cur.fetchall():
            logical, physical, ftype = row[0], row[1], row[2]
            m = re.search(r"\.([A-Za-z0-9]+)$", physical or "")
            ext = "." + m.group(1) if m else ("" if ftype == "S" else (".ldf" if ftype == "L" else ".mdf"))
            folder = log_dir if ftype == "L" else data_dir
            moves.append("MOVE %s TO %s" % (qlit(logical), qlit("%s%s_%s%s" % (
                folder, safe_name(target), safe_name(logical), ext))))
        if not moves:
            raise ValueError("В копии не найдено файлов базы")
        cur.execute("RESTORE DATABASE %s FROM %s WITH %s, RECOVERY, CHECKSUM"
                    % (qid(target), src, ", ".join(moves)))
        return "%s -> %s (новая база)" % (path, target)


def test_storage(st):
    """Пишет небольшую копию системной базы model в выбранное хранилище."""
    kind, path = build_target(st, "model", filename=TEST_FILE)
    with connect() as conn:
        cur = conn.cursor()
        if st["type"] == "s3":
            ensure_s3_credential(cur, st)
        cur.execute(_backup_sql("model", kind, path, "mssql-backup-web write test"))
    return path
