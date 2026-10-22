"""Тесты API без реального SQL Server и LDAP: MSSQL и LDAP подменены заглушками.

Запуск:  python3 tests/test_app.py        (нужен Flask; ldap3 — если нет, подставляется заглушка)
"""
import datetime
import json
import os
import re
import sys
import tempfile
import threading
import time
import types
import unittest

TMP = tempfile.mkdtemp()
os.environ.update(DATA_DIR=TMP, ADMIN_USER="admin", ADMIN_PASSWORD="adminpw", MSSQL_HOST="sql.test")
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))

try:
    import ldap3  # noqa: F401
    STUBBED_LDAP3 = False
except ImportError:
    # Минимальная заглушка ldap3: проверяется наша логика, а не сама библиотека
    STUBBED_LDAP3 = True
    m = types.ModuleType("ldap3")
    for name, val in dict(Server=object, Connection=object, Tls=object, SUBTREE="SUBTREE", BASE="BASE", NONE="NONE").items():
        setattr(m, name, val)
    core = types.ModuleType("ldap3.core")
    exc = types.ModuleType("ldap3.core.exceptions")
    exc.LDAPException = type("LDAPException", (Exception,), {})
    utils = types.ModuleType("ldap3.utils")
    conv = types.ModuleType("ldap3.utils.conv")
    conv.escape_filter_chars = lambda s: "".join(
        "\\%02x" % ord(c) if c in "\\*()\x00" else c for c in s)
    sys.modules.update({"ldap3": m, "ldap3.core": core, "ldap3.core.exceptions": exc,
                        "ldap3.utils": utils, "ldap3.utils.conv": conv})

import access  # noqa: E402
import config  # noqa: E402
import history  # noqa: E402
import ldap_auth  # noqa: E402
import mssql_ops  # noqa: E402
import app as webapp  # noqa: E402

H = {"X-Requested-With": "fetch"}
webapp.time.sleep = lambda s: None
import logging  # noqa: E402
logging.getLogger("backup").setLevel(logging.CRITICAL)   # ожидаемые ошибки задач не засоряют вывод


@webapp.app.get("/_probe")      # эндпоинт без записи в PERMS (регистрируется до первого запроса)
def _probe():
    return "x"

# ---------- заглушка LDAP ----------
USERS = {
    "alice": ("cn=alice,ou=u,dc=ex", "alicepw", ["CN=Viewers,OU=G,DC=ex"]),
    "bob": ("cn=bob,ou=u,dc=ex", "bobpw", ["CN=Operators,OU=G, DC=ex"]),            # пробел после запятой
    "carol": ("cn=carol,ou=u,dc=ex", "carolpw", ["cn=admins,ou=g,dc=ex", "CN=Viewers,OU=G,DC=ex"]),
    "dave": ("cn=dave,ou=u,dc=ex", "davepw", ["CN=Other,OU=G,DC=ex"]),
    "erin": ("cn=erin,ou=u,dc=ex", "erinpw", ["CN=Operators,OU=G,DC=ex"]),
    "frank": ("cn=frank,ou=u,dc=ex", "frankpw", ["CN=Operators,OU=G,DC=ex"]),
}


class FakeEntry:
    def __init__(self, name):
        dn, _, groups = USERS[name]
        self.entry_dn = dn
        self.entry_attributes_as_dict = {"memberOf": groups, "displayName": [name.title()], "cn": [name]}


class FakeLdap:
    result = {"description": "ok"}

    def __init__(self):
        self.entries = []

    def search(self, base, flt, search_scope=None, attributes=None, size_limit=0):
        m = re.match(r"\(sAMAccountName=(.*)\)$", flt)
        name = m.group(1) if m else None
        self.entries = [FakeEntry(n) for n in USERS if n == name]
        return bool(self.entries) or flt == "(objectClass=*)"

    def unbind(self):
        pass


def fake_ldap_connect(cfg, user=None, password=None):
    if user == "cn=svc,dc=ex" and password == "svcpw":
        return FakeLdap()
    for dn, pw, _ in USERS.values():
        if user == dn and password and password == pw:
            return FakeLdap()
    raise ldap_auth.AuthError("Сервер отклонил привязку: invalidCredentials")


ldap_auth._connect = fake_ldap_connect


# ---------- заглушка SQL Server ----------
class Fake:
    sqls = []
    gate = None
    existing = {"master", "model", "sales", "sales2"}
    backups = [("sales", datetime.datetime(2026, 10, 20, 3, 0, 0), 1000, 300,
                "/var/opt/mssql/backup/sales_20261020_030000.bak", "sa", 101)]


class FakeCursor:
    def __init__(self):
        self.rows = []

    def execute(self, sql):
        Fake.sqls.append(sql)
        self.rows = []
        if sql.startswith("BACKUP") and Fake.gate:
            Fake.gate.wait(5)
        if "FROM sys.databases WHERE state_desc" in sql:
            self.rows = [(n,) for n in sorted(Fake.existing)] + [("tempdb",)]
        elif "sys.master_files" in sql:
            self.rows = [(0, "/data/sales2.mdf"), (1, "/log/sales2_log.ldf")]
        elif "SELECT 1 FROM sys.databases WHERE name" in sql:
            name = re.search(r"name = N'(.*)'$", sql).group(1)
            self.rows = [(1,)] if name in Fake.existing else []
        elif "msdb.dbo.backupset" in sql:
            m = re.search(r"physical_device_name = N'(.*?)'\s*(?:\n|$)", sql)
            d = re.search(r"bs.database_name = N'(.*?)'", sql)
            i = re.search(r"bs.backup_set_id = (\d+)", sql)
            t = re.search(r"SELECT TOP (\d+)", sql)
            rows = [b for b in Fake.backups if (not m or b[4] == m.group(1)) and (not d or b[0] == d.group(1))
                    and (not i or b[6] == int(i.group(1)))]
            rows.sort(key=lambda b: (b[1], b[6]), reverse=True)
            off = re.search(r"OFFSET (\d+) ROWS FETCH NEXT (\d+) ROWS ONLY", sql)
            if "SELECT COUNT(*)" in sql:
                self.rows = [(len(rows),)]
            elif off:
                self.rows = rows[int(off.group(1)):int(off.group(1)) + int(off.group(2))]
            else:
                self.rows = rows[:int(t.group(1))] if t else rows
        elif "SERVERPROPERTY" in sql:
            self.rows = [("/var/opt/mssql/data/", "/var/opt/mssql/log/")]
        elif "RESTORE FILELISTONLY" in sql:
            self.rows = [("sales", "/var/opt/mssql/data/sales.mdf", "D"),
                         ("sales_log", "/var/opt/mssql/data/sales_log.ldf", "L")]

    def fetchall(self):
        return self.rows

    def fetchone(self):
        return self.rows[0] if self.rows else None


class FakeConn:
    def cursor(self):
        return FakeCursor()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


mssql_ops.connect = lambda: FakeConn()


def wait_job(client, hid, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        row = client.get("/history/%d" % hid).get_json()
        if row["status"] not in ("running", "queued"):
            return row
        time.sleep(0.02)
    raise AssertionError("задача не завершилась")


def last_sql(prefix):
    return [s for s in Fake.sqls if s.lstrip().startswith(prefix)][-1]


LDAP_CFG = {"enabled": True, "host": "ldap.test", "base_dn": "dc=ex", "bind_dn": "cn=svc,dc=ex",
            "bind_password": "svcpw", "full_group_dn": "CN=Admins,OU=G,DC=ex",
            "operator_group_dn": "CN=Operators,OU=G,DC=ex", "viewer_group_dn": "CN=Viewers,OU=G,DC=ex"}


def login(user, pw):
    c = webapp.app.test_client()
    r = c.post("/auth/login", json={"username": user, "password": pw}, headers=H)
    return c, r


def admin():
    c, r = login("admin", "adminpw")
    assert r.status_code == 200, r.get_json()
    return c


def ldap_on():
    r = admin().put("/settings/ldap", json=LDAP_CFG, headers=H)
    assert r.status_code == 200, r.get_json()


def reset_access():
    """Чистое состояние прав: без групп и личных списков баз."""
    for g in access.list_groups():
        access.delete_group(g["id"])
    for u in access.list_users():
        access.set_user(u["name"], [], [], [], [])


def login_admin_info(c):
    return c.get("/info").get_json()


class Tests(unittest.TestCase):
    def setUp(self):
        Fake.sqls.clear()
        Fake.gate = None
        webapp._fails.clear()

    # --- доступ ---
    def test_01_unauthenticated(self):
        c = webapp.app.test_client()
        self.assertEqual(c.get("/databases", headers=H).status_code, 401)
        self.assertFalse(c.get("/auth/me").get_json()["authenticated"])
        r = c.post("/auth/login", json={"username": "admin", "password": "adminpw"})   # без X-Requested-With
        self.assertEqual(r.status_code, 403)

    def test_02_local_admin(self):
        c, r = login("admin", "adminpw")
        u = r.get_json()["user"]
        self.assertEqual((r.status_code, u["role"]), (200, "full"))
        self.assertIn("settings", u["perms"])
        self.assertEqual(login("admin", "bad")[1].status_code, 401)
        self.assertEqual(login("admin", "")[1].status_code, 401)

    def test_03_ldap_settings_and_roles(self):
        a = admin()
        r = a.put("/settings/ldap", json=LDAP_CFG, headers=H)
        self.assertEqual(r.status_code, 200, r.get_json())
        body = a.get("/settings/ldap").get_json()
        self.assertNotIn("bind_password", body)
        self.assertTrue(body["bind_password_set"])

        expected = {"alice": "viewer", "bob": "operator", "carol": "full"}
        for name, role in expected.items():
            c, r = login(name, USERS[name][1])
            self.assertEqual((name, r.status_code), (name, 200), r.get_json())
            self.assertEqual(r.get_json()["user"]["role"], role, name)
        for name, pw in (("dave", "davepw"), ("alice", "wrong"), ("alice", ""), ("*", "x"), ("nobody", "x")):
            self.assertEqual(login(name, pw)[1].status_code, 401, name)

    def test_03b_version(self):
        r = webapp.app.test_client().get("/health").get_json()                # доступна без входа (экран входа)
        ver = open(os.path.join(os.path.dirname(os.path.abspath(webapp.__file__)), "VERSION")).read().strip()
        self.assertEqual(r["version"], ver)
        self.assertRegex(ver, r"^\d+\.\d+\.\d+$")

    def test_04_permissions(self):
        webapp.app.config["TESTING"] = True
        config.save("ldap", config.build("ldap", LDAP_CFG, config.load("ldap")))
        viewer, operator, full = login("alice", "alicepw")[0], login("bob", "bobpw")[0], admin()
        self.assertEqual(viewer.get("/databases").status_code, 200)
        self.assertEqual(viewer.get("/info").status_code, 403)             # место хранения и адрес SQL — только администратору
        self.assertEqual(operator.get("/info").status_code, 403)
        self.assertIn("storage", login_admin_info(full))
        self.assertEqual(viewer.get("/history").status_code, 403)         # история всего сервера — только полный доступ
        self.assertEqual(operator.get("/history").status_code, 403)
        self.assertEqual(full.get("/history").status_code, 200)
        self.assertEqual(viewer.get("/backups").status_code, 403)         # список копий — только администратору
        self.assertEqual(operator.get("/backups").status_code, 403)
        self.assertEqual(viewer.get("/queue").status_code, 200)           # очередь видят все
        for method, url in (("post", "/backup"), ("post", "/restore"), ("get", "/settings/storage"),
                            ("get", "/settings/ldap"), ("put", "/settings/ldap"), ("post", "/settings/storage/test")):
            self.assertEqual(getattr(viewer, method)(url, json={}, headers=H).status_code, 403, "viewer " + url)
        for url in ("/settings/ldap", "/settings/storage"):
            self.assertEqual(operator.get(url).status_code, 403, "operator " + url)
        self.assertEqual(full.get("/settings/storage").status_code, 200)
        self.assertEqual(operator.post("/backup", json={"database": "sales"}, headers=H).status_code, 403)   # база не видна
        full.put("/access/users/bob", json={"backup_dbs": ["sales"], "source_dbs": ["sales"], "groups": []}, headers=H)
        r = operator.post("/backup", json={"database": "sales"}, headers=H)
        self.assertEqual(r.status_code, 202)
        wait_job(operator, r.get_json()["id"])

    def test_05_ldap_test_endpoint(self):
        a = admin()
        r = a.post("/settings/ldap/test", json={"config": {}, "test_user": "alice", "test_password": "alicepw"}, headers=H).get_json()
        self.assertTrue(r["ok"], r)
        self.assertIn("Просмотр", r["user"])
        r = a.post("/settings/ldap/test", json={"config": {}, "test_user": "alice", "test_password": "x"}, headers=H).get_json()
        self.assertFalse(r["ok"])
        r = a.post("/settings/ldap/test", json={"config": {}, "test_user": "dave", "test_password": "davepw"}, headers=H).get_json()
        self.assertIn("ни в одну", r["error"])

    def test_06_validation(self):
        a = admin()
        bad = [
            ("/settings/ldap", {"enabled": True, "full_group_dn": "", "operator_group_dn": "", "viewer_group_dn": ""}),
            ("/settings/ldap", {"user_filter": "(uid=x)"}),
            ("/settings/ldap", {"port": 0}),
            ("/settings/ldap", {"security": "plain"}),
            ("/settings/storage", {"type": "smb", "smb_path": "C:\\backups"}),
            ("/settings/storage", {"type": "s3", "s3_endpoint": "h", "s3_bucket": "b", "s3_access_key": "a:b", "s3_secret_key": "s"}),
            ("/settings/storage", {"type": "s3", "s3_endpoint": "", "s3_bucket": "b", "s3_access_key": "a", "s3_secret_key": "s"}),
            ("/settings/storage", {"type": "ftp"}),
        ]
        for url, payload in bad:
            self.assertEqual(a.put(url, json=payload, headers=H).status_code, 400, (url, payload))

    # --- хранилища и бэкап ---
    def _backup(self, client, db="sales"):
        r = client.post("/backup", json={"database": db}, headers=H)
        self.assertEqual(r.status_code, 202, r.get_json())
        return wait_job(client, r.get_json()["id"])

    def test_10_backup_local(self):
        a = admin()
        self.assertEqual(a.put("/settings/storage", json={"type": "local", "local_path": "/var/opt/mssql/backup/"}, headers=H).status_code, 200)
        row = self._backup(a)
        self.assertEqual(row["status"], "ok", row)
        sql = last_sql("BACKUP")
        self.assertIn("BACKUP DATABASE [sales] TO DISK = N'/var/opt/mssql/backup/sales_", sql)
        self.assertIn("COPY_ONLY", sql)
        self.assertIn("INIT", sql)
        self.assertNotIn("URL", sql)

    def test_11_backup_windows_and_smb(self):
        a = admin()
        a.put("/settings/storage", json={"type": "local", "local_path": "D:\\Backups"}, headers=H)
        self._backup(a)
        self.assertIn("TO DISK = N'D:\\Backups\\sales_", last_sql("BACKUP"))
        r = a.put("/settings/storage", json={"type": "smb", "smb_path": "//fs/backups/sql/"}, headers=H)
        self.assertEqual(r.get_json()["smb_path"], "\\\\fs\\backups\\sql")
        self._backup(a)
        self.assertIn("TO DISK = N'\\\\fs\\backups\\sql\\sales_", last_sql("BACKUP"))

    def test_12_backup_s3(self):
        a = admin()
        r = a.put("/settings/storage", json={"type": "s3", "s3_endpoint": "https://minio.local:9000", "s3_bucket": "b",
                                             "s3_prefix": "/sql/", "s3_access_key": "AKIA", "s3_secret_key": "TOPSECRET"}, headers=H)
        self.assertEqual(r.status_code, 200, r.get_json())
        body = r.get_json()
        self.assertEqual((body["s3_endpoint"], body["s3_port"], body["s3_prefix"]), ("minio.local", 9000, "sql"))
        self.assertNotIn("s3_secret_key", body)
        self.assertTrue(body["s3_secret_key_set"])
        row = self._backup(a)
        self.assertEqual(row["status"], "ok", row)
        joined = "\n".join(Fake.sqls)
        self.assertIn("CREATE CREDENTIAL [s3://minio.local:9000/b] WITH IDENTITY = 'S3 Access Key', SECRET = N'AKIA:TOPSECRET'", joined)
        sql = last_sql("BACKUP")
        self.assertIn("TO URL = N's3://minio.local:9000/b/sql/sales_", sql)
        self.assertIn("FORMAT", sql)
        self.assertIn("MAXTRANSFERSIZE = 20971520", sql)
        # секрет не должен попадать в историю и в ответы
        everything = str(a.get("/history?limit=200").get_json()) + str(a.get("/settings/storage").get_json())
        self.assertNotIn("TOPSECRET", everything)
        # пустой secret при сохранении = «оставить прежний»
        a.put("/settings/storage", json={"s3_secret_key": ""}, headers=H)
        self.assertEqual(config.load("storage")["s3_secret_key"], "TOPSECRET")
        # виртуальный хост, порт 443 не пишется
        a.put("/settings/storage", json={"s3_endpoint": "s3.eu-central-1.amazonaws.com", "s3_port": 443, "s3_virtual_host": True}, headers=H)
        self.assertEqual(mssql_ops.s3_base(config.load("storage")), "s3://b.s3.eu-central-1.amazonaws.com")

    def test_13_backup_errors(self):
        a = admin()
        a.put("/settings/storage", json={"type": "local", "local_path": "/var/opt/mssql/backup"}, headers=H)
        row = self._backup(a, "nope")
        self.assertEqual(row["status"], "error")
        self.assertIn("не найдена", row["details"])
        self.assertEqual(a.post("/backup", json={}, headers=H).status_code, 400)

    def test_14_queue_runs_one_job_at_a_time(self):
        a = admin()
        a.put("/settings/storage", json={"type": "local", "local_path": "/var/opt/mssql/backup"}, headers=H)
        Fake.gate = threading.Event()
        r1 = a.post("/backup", json={"database": "sales"}, headers=H)
        self.assertEqual(r1.status_code, 202)
        r2 = a.post("/backup", json={"database": "model"}, headers=H)       # не отказ, а очередь
        self.assertEqual(r2.status_code, 202)
        self.assertEqual((r1.get_json()["position"], r2.get_json()["position"]), (1, 2))
        self.assertEqual(a.post("/settings/storage/test", json={"config": {}}, headers=H).status_code, 409)
        Fake.gate.set()
        self.assertEqual(wait_job(a, r1.get_json()["id"])["status"], "ok")
        self.assertEqual(wait_job(a, r2.get_json()["id"])["status"], "ok")
        order = [x for x in Fake.sqls if x.startswith("BACKUP DATABASE")]
        self.assertTrue("[sales]" in order[0] and "[model]" in order[1], order)

    def test_15_storage_test(self):
        a = admin()
        a.put("/settings/storage", json={"type": "local", "local_path": "/var/opt/mssql/backup"}, headers=H)
        r = a.post("/settings/storage/test", json={"config": {}}, headers=H).get_json()
        self.assertTrue(r["ok"], r)
        self.assertIn("BACKUP DATABASE [model]", last_sql("BACKUP"))
        self.assertIn("mssql_backup_web_write_test.bak", last_sql("BACKUP"))
        a.get("/backups")
        self.assertIn("NOT LIKE N'%mssql_backup_web_write_test.bak'", last_sql("SELECT bs.database_name"))

    # --- восстановление ---
    def test_16_queue_order_cancel_and_visibility(self):
        ldap_on(); reset_access()
        a = admin()
        a.put("/settings/storage", json={"type": "local", "local_path": "/var/opt/mssql/backup"}, headers=H)
        bob, alice = login("bob", "bobpw")[0], login("alice", "alicepw")[0]
        a.put("/access/users/bob", json={"backup_dbs": ["sales2"], "source_dbs": ["sales2"], "groups": []}, headers=H)
        Fake.gate = threading.Event()
        r1 = a.post("/backup", json={"database": "sales"}, headers=H).get_json()["id"]
        r2 = bob.post("/backup", json={"database": "sales2"}, headers=H).get_json()["id"]
        r3 = a.post("/backup", json={"database": "master"}, headers=H).get_json()["id"]
        ours = lambda c, key="items": [i for i in c.get("/queue").get_json()[key] if i["id"] in (r1, r2, r3)]
        q = ours(alice)                                      # очередь всех пользователей видна и роли «Просмотр»
        self.assertEqual([(i["id"], i["status"], i["position"]) for i in q],
                         [(r1, "running", 1), (r2, "queued", 2), (r3, "queued", 3)])
        self.assertEqual([i["username"] for i in q], ["admin", "bob", "admin"])
        self.assertEqual([i["can_cancel"] for i in ours(alice)], [False, False, False])
        self.assertEqual([i["can_cancel"] for i in ours(bob)], [False, True, False])     # свою
        self.assertEqual([i["can_cancel"] for i in ours(a)], [False, True, True])         # админ — любую ожидающую
        self.assertEqual(alice.post("/queue/%d/cancel" % r2, headers=H).status_code, 403)
        self.assertEqual(bob.post("/queue/%d/cancel" % r3, headers=H).status_code, 403)
        self.assertEqual(a.post("/queue/%d/cancel" % r1, headers=H).status_code, 409)     # уже выполняется
        self.assertEqual(a.post("/queue/999999/cancel", headers=H).status_code, 404)
        self.assertEqual(bob.post("/queue/%d/cancel" % r2, headers=H).status_code, 200)
        Fake.gate.set()
        wait_job(a, r1); wait_job(a, r3)
        order = [x for x in Fake.sqls if x.startswith("BACKUP DATABASE")]
        self.assertTrue(len(order) == 2 and "[sales]" in order[0] and "[master]" in order[1], order)   # [model] снята
        self.assertEqual(a.get("/history/%d" % r2).get_json()["status"], "cancelled")
        self.assertEqual([i["status"] for i in ours(a, "recent")], ["ok", "cancelled", "ok"])    # админ видит все: r3, r2, r1
        self.assertEqual([i["id"] for i in ours(bob, "recent")], [r2])                           # оператор — только свои
        self.assertEqual(ours(alice, "recent"), [])                                              # у «Просмотра» своих нет
        self.assertEqual(ours(alice), [])

        # администратор снимает чужую ожидающую задачу
        Fake.gate = threading.Event()
        a.post("/backup", json={"database": "sales"}, headers=H)
        r5 = bob.post("/backup", json={"database": "sales2"}, headers=H).get_json()["id"]
        self.assertEqual(a.post("/queue/%d/cancel" % r5, headers=H).status_code, 200)
        Fake.gate.set()

    def test_17_copies_hidden_and_restore_by_database(self):
        ldap_on(); reset_access()
        a = admin()
        bob, alice = login("bob", "bobpw")[0], login("alice", "alicepw")[0]
        path = Fake.backups[0][4]
        a.put("/access/users/bob", json={"backup_dbs": ["sales"], "source_dbs": ["sales"], "groups": []}, headers=H)
        self.assertEqual(bob.get("/backups").status_code, 403)           # «Сделанные копии» — только администратору
        self.assertEqual(a.get("/backups").status_code, 200)
        self.assertEqual(alice.get("/restore/sources").status_code, 403)
        src = bob.get("/restore/sources").get_json()["sources"]
        self.assertEqual([s["database"] for s in src], ["sales"])
        self.assertNotIn(path, str(src))                                  # пути к файлам оператору не отдаются
        # оператор выбирает базу, а не файл: берётся последняя копия
        r = bob.post("/restore", json={"path": path, "target": "x", "new": True}, headers=H)
        self.assertEqual(r.status_code, 403)
        r = bob.post("/restore", json={"database": "nodb", "target": "x", "new": True}, headers=H)
        self.assertEqual(r.status_code, 404)
        self.assertIn("нет копий", r.get_json()["error"])
        self.assertEqual(bob.post("/restore", json={"target": "x", "new": True}, headers=H).status_code, 400)
        a.put("/access/users/bob", json={"allowed_dbs": ["sales"], "backup_dbs": ["sales", "sales2", "model"], "source_dbs": ["sales", "sales2", "model"], "groups": []}, headers=H)
        r = bob.post("/restore", json={"database": "sales", "target": "sales", "confirm": "sales"}, headers=H)
        self.assertEqual(r.status_code, 202, r.get_json())
        wait_job(bob, r.get_json()["id"])
        self.assertIn("FROM DISK = N'%s'" % path, last_sql("RESTORE DATABASE"))
        # конкретную копию администратор выбрать может
        r = a.post("/restore", json={"path": path, "target": "sales", "confirm": "sales"}, headers=H)
        self.assertEqual(wait_job(a, r.get_json()["id"])["status"], "ok")

    def test_18_choose_copy(self):
        ldap_on(); reset_access()
        a = admin()
        bob = login("bob", "bobpw")[0]
        a.put("/access/users/bob", json={"allowed_dbs": ["sales"], "backup_dbs": ["sales", "sales2", "model", "hr"], "source_dbs": ["sales", "sales2", "model", "hr"], "groups": []}, headers=H)
        old = ("sales", datetime.datetime(2026, 10, 10, 3, 0, 0), 500, 100, "/var/opt/mssql/backup/sales_old.bak", "sa", 100)
        other = ("hr", datetime.datetime(2026, 10, 21, 3, 0, 0), 5, 5, "/var/opt/mssql/backup/hr.bak", "sa", 200)
        Fake.backups.extend([old, other])
        try:
            lst = bob.get("/restore/copies?database=sales").get_json()["copies"]
            self.assertEqual([c["id"] for c in lst], [101, 100])               # от новых к старым
            self.assertNotIn("/var/opt", str(lst))                            # путей нет
            self.assertEqual(bob.get("/restore/copies").status_code, 400)
            self.assertEqual(login("alice", "alicepw")[0].get("/restore/copies?database=sales").status_code, 403)
            r = bob.post("/restore", json={"database": "sales", "copy": 100, "target": "sales", "confirm": "sales"}, headers=H)
            self.assertEqual(r.status_code, 202, r.get_json())
            wait_job(bob, r.get_json()["id"])
            self.assertIn("FROM DISK = N'/var/opt/mssql/backup/sales_old.bak'", last_sql("RESTORE DATABASE"))
            # копия другой базы / несуществующая / некорректный id
            r = bob.post("/restore", json={"database": "sales", "copy": 200, "target": "sales", "confirm": "sales"}, headers=H)
            self.assertEqual(r.status_code, 400)
            self.assertEqual(bob.post("/restore", json={"database": "sales", "copy": 999, "target": "sales", "confirm": "sales"}, headers=H).status_code, 404)
            self.assertEqual(bob.post("/restore", json={"database": "sales", "copy": "1", "target": "sales", "confirm": "sales"}, headers=H).status_code, 400)
            # без copy — последняя
            r = bob.post("/restore", json={"database": "sales", "target": "sales", "confirm": "sales"}, headers=H)
            wait_job(bob, r.get_json()["id"])
            self.assertIn("sales_20261020_030000.bak", last_sql("RESTORE DATABASE"))
        finally:
            Fake.backups.remove(old); Fake.backups.remove(other)

    def test_19_notifications(self):
        import http.server, socketserver
        import notify
        got_hooks, got_mail = [], []

        class Hook(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                got_hooks.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
            def log_message(self, *a): pass

        class Smtp(socketserver.StreamRequestHandler):      # минимальный SMTP без шифрования
            def handle(self):
                w = lambda t: self.wfile.write((t + "\r\n").encode())
                w("220 fake"); data = False; buf = []
                while True:
                    line = self.rfile.readline().decode(errors="replace")
                    if not line: return
                    if data:
                        if line == ".\r\n":
                            got_mail.append("".join(buf)); data = False; w("250 queued")
                        else: buf.append(line)
                        continue
                    cmd = line[:4].upper()
                    if cmd == "EHLO": w("250 fake")
                    elif cmd == "DATA": data = True; w("354 go")
                    elif cmd == "QUIT": w("221 bye"); return
                    else: w("250 ok")

        hs = http.server.HTTPServer(("127.0.0.1", 0), Hook)
        ss = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Smtp); ss.daemon_threads = True
        for srv in (hs, ss): threading.Thread(target=srv.serve_forever, daemon=True).start()
        try:
            a = admin()
            self.assertEqual(a.put("/settings/notify", json={"email_enabled": True, "smtp_host": ""}, headers=H).status_code, 400)
            self.assertEqual(a.put("/settings/notify", json={"webhook_enabled": True, "webhook_url": "ftp://x"}, headers=H).status_code, 400)
            hook = "http://127.0.0.1:%d/hook/TOKEN123" % hs.server_address[1]
            cfg = {"email_enabled": True, "smtp_host": "127.0.0.1", "smtp_port": ss.server_address[1], "smtp_security": "none",
                   "mail_from": "backup@example.com", "mail_to": "a@example.com, b@example.com",
                   "webhook_enabled": True, "webhook_url": hook, "smtp_password": "SMTPSECRET",
                   "ev_restore_ok": False}
            r = a.put("/settings/notify", json=cfg, headers=H)
            self.assertEqual(r.status_code, 200, r.get_json())
            body = r.get_json()
            self.assertTrue(body["smtp_password_set"] and body["webhook_url_set"])
            self.assertNotIn("SMTPSECRET", str(body)); self.assertNotIn("TOKEN123", str(body))
            self.assertNotIn("SMTPSECRET", str(a.get("/history").get_json()))
            # тест webhook (проверяет сохранённый секрет, если поле пустое)
            r = a.post("/settings/notify/test", json={"channel": "webhook", "config": {}}, headers=H)
            self.assertTrue(r.get_json()["ok"], r.get_json())
            self.assertEqual(got_hooks[-1]["event"], "test")
            # копия -> и письмо, и webhook
            n0 = len(got_hooks)
            orig_find = mssql_ops.find_backup
            mssql_ops.find_backup = lambda conn, path: {"size": 5000000, "compressed_size": 1234567890}
            try:
                r = a.post("/backup", json={"database": "sales"}, headers=H)
                self.assertEqual(wait_job(a, r.get_json()["id"])["status"], "ok")
                for _ in range(50):
                    if len(got_hooks) > n0 and got_mail: break
                    threading.Event().wait(0.1)
            finally:
                mssql_ops.find_backup = orig_find
            self.assertEqual(got_hooks[-1]["event"], "backup_ok"); self.assertEqual(got_hooks[-1]["database"], "sales")
            txt = got_hooks[-1]["text"]                      # «Результат»: только имя файла и размер, без пути
            self.assertRegex(txt, r"Результат: sales_\d{8}_\d{6}\.bak, 1\.23 ГБ")
            self.assertNotIn("/var/opt", txt)
            self.assertIn("Subject:", got_mail[-1]); self.assertIn("Резервная", got_mail[-1] if "Subject: =?" not in got_mail[-1] else "Резервная")
            # восстановление отключено в событиях -> сообщения нет
            n1, m1 = len(got_hooks), len(got_mail)
            path = Fake.backups[0][4]
            r = a.post("/restore", json={"path": path, "target": "sales", "confirm": "sales"}, headers=H)
            wait_job(a, r.get_json()["id"]); threading.Event().wait(0.4)
            self.assertEqual((len(got_hooks), len(got_mail)), (n1, m1))
            # ошибка копии -> сообщение об ошибке
            a.put("/settings/notify", json={"ev_restore_ok": False, "webhook_url": hook}, headers=H)
            orig = mssql_ops.run_backup
            mssql_ops.run_backup = lambda st, db: (_ for _ in ()).throw(RuntimeError("диск полон"))
            try:
                r = a.post("/backup", json={"database": "sales"}, headers=H)
                self.assertEqual(wait_job(a, r.get_json()["id"])["status"], "error")
            finally:
                mssql_ops.run_backup = orig
            for _ in range(50):
                if got_hooks[-1]["event"] == "backup_error": break
                threading.Event().wait(0.1)
            self.assertEqual(got_hooks[-1]["event"], "backup_error"); self.assertIn("диск полон", got_hooks[-1]["text"])
            # недоступный получатель: ошибка пишется в историю, очередь не страдает
            a.put("/settings/notify", json={"email_enabled": False, "webhook_url": "http://127.0.0.1:1/x"}, headers=H)
            r = a.post("/backup", json={"database": "sales"}, headers=H)
            self.assertEqual(wait_job(a, r.get_json()["id"])["status"], "ok")
            for _ in range(60):
                items = a.get("/history?limit=20").get_json()["items"]
                if any(i["action"] == "notify" for i in items): break
                threading.Event().wait(0.1)
            self.assertTrue(any(i["action"] == "notify" and i["status"] == "error" for i in items))
            self.assertNotIn("TOKEN123", str(items))
        finally:
            hs.shutdown(); ss.shutdown()
            config.save("notify", dict(config.DEFAULTS["notify"]))

    def test_19b_telegram_and_bitrix24(self):
        import http.server
        import notify
        calls = []

        class H2(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                calls.append((self.path, body))
                if "BADTOKEN" in self.path:
                    code, out = 401, {"ok": False, "description": "Unauthorized"}
                elif self.path.startswith("/rest/") and body.get("DIALOG_ID") == "999":
                    code, out = 200, {"error": "ACCESS_ERROR", "error_description": "нет доступа"}
                elif self.path.startswith("/rest/"):
                    code, out = 200, {"result": 123}
                else:
                    code, out = 200, {"ok": True}
                raw = json.dumps(out).encode()
                self.send_response(code); self.send_header("Content-Length", str(len(raw))); self.end_headers()
                self.wfile.write(raw)
            def log_message(self, *a): pass

        srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H2)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % srv.server_address[1]
        old_api, notify.TELEGRAM_API = notify.TELEGRAM_API, base
        tok = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        try:
            a = admin()
            put = lambda d: a.put("/settings/notify", json=d, headers=H)
            self.assertEqual(put({"telegram_enabled": True, "telegram_token": "x", "telegram_chat": "1"}).status_code, 400)
            self.assertEqual(put({"telegram_enabled": True, "telegram_token": tok, "telegram_chat": "abc"}).status_code, 400)
            self.assertEqual(put({"bitrix_enabled": True, "bitrix_url": base + "/x", "bitrix_dialog": "1"}).status_code, 400)
            self.assertEqual(put({"bitrix_enabled": True, "bitrix_url": base + "/rest/1/abc/", "bitrix_dialog": "x"}).status_code, 400)
            r = put({"telegram_enabled": True, "telegram_token": tok, "telegram_chat": "-1001234",
                     "bitrix_enabled": True, "bitrix_url": base + "/rest/1/abc/", "bitrix_dialog": "chat15"})
            self.assertEqual(r.status_code, 200, r.get_json())
            pub = r.get_json()
            self.assertTrue(pub["telegram_token_set"] and pub["bitrix_url_set"])
            self.assertNotIn(tok, str(pub)); self.assertNotIn("/rest/1/abc", str(pub))
            # тесты каналов
            r = a.post("/settings/notify/test", json={"channel": "telegram", "config": {}}, headers=H).get_json()
            self.assertTrue(r["ok"], r)
            self.assertEqual(calls[-1][0], "/bot%s/sendMessage" % tok)
            self.assertEqual(calls[-1][1]["chat_id"], "-1001234")
            r = a.post("/settings/notify/test", json={"channel": "bitrix24", "config": {}}, headers=H).get_json()
            self.assertTrue(r["ok"], r)
            self.assertEqual(calls[-1][0], "/rest/1/abc/im.message.add.json")
            self.assertEqual(calls[-1][1]["DIALOG_ID"], "chat15")
            # ошибки каналов: понятный текст без токена/URL
            r = a.post("/settings/notify/test", json={"channel": "bitrix24", "config": {"bitrix_dialog": "999"}}, headers=H).get_json()
            self.assertFalse(r["ok"]); self.assertIn("нет доступа", r["error"]); self.assertNotIn("/rest/1/abc", r["error"])
            r = a.post("/settings/notify/test", json={"channel": "telegram", "config": {
                "telegram_token": "999999:BADTOKENBADTOKENBADTOKEN"}}, headers=H).get_json()
            self.assertFalse(r["ok"]); self.assertIn("Unauthorized", r["error"]); self.assertNotIn("BADTOKEN", r["error"])
            self.assertEqual(a.post("/settings/notify/test", json={"channel": "icq"}, headers=H).status_code, 400)
            # реальная задача -> оба канала
            n = len(calls)
            r = a.post("/backup", json={"database": "sales"}, headers=H)
            self.assertEqual(wait_job(a, r.get_json()["id"])["status"], "ok")
            for _ in range(50):
                if len(calls) >= n + 2: break
                threading.Event().wait(0.1)
            paths = sorted(c[0].split("/")[1][:3] for c in calls[n:])
            self.assertEqual(paths, ["bot", "res"][::-1] if False else sorted(["bot", "res"]), calls[n:])
            tg = [c for c in calls[n:] if c[0].startswith("/bot")][0][1]
            self.assertIn("sales", tg["text"])
        finally:
            notify.TELEGRAM_API = old_api
            srv.shutdown()
            config.save("notify", dict(config.DEFAULTS["notify"]))

    def test_19c_telegram_proxy(self):
        import base64, http.server, socket, socketserver
        import notify
        seen = {"http": [], "socks": []}

        class Tg(http.server.BaseHTTPRequestHandler):          # «Telegram»
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                seen.setdefault("tg", []).append(self.path)
                raw = b'{"ok": true}'
                self.send_response(200); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
            def log_message(self, *a): pass

        class HttpProxy(http.server.BaseHTTPRequestHandler):   # HTTP-прокси: получает абсолютный URL
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                seen["http"].append((self.path, self.headers.get("Proxy-Authorization")))
                raw = b'{"ok": true}'
                self.send_response(200); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
            def log_message(self, *a): pass

        class Socks(socketserver.BaseRequestHandler):          # SOCKS5 с логином/паролем, ретранслирует на «Telegram»
            def handle(self):
                c = self.request
                def need(n):
                    b = b""
                    while len(b) < n:
                        d = c.recv(n - len(b))
                        if not d: raise OSError("eof")
                        b += d
                    return b
                need(1); n = need(1)[0]; methods = need(n)
                if 2 not in methods:
                    c.sendall(b"\x05\xff"); return
                c.sendall(b"\x05\x02")
                need(1); u = need(need(1)[0]).decode(); pw = need(need(1)[0]).decode()
                if (u, pw) != ("pu", "ppw"):
                    c.sendall(b"\x01\x01"); return
                c.sendall(b"\x01\x00")
                need(3); atyp = need(1)[0]
                host = need(need(1)[0]).decode() if atyp == 3 else socket.inet_ntoa(need(4))
                port = int.from_bytes(need(2), "big")
                seen["socks"].append((host, port))
                up = socket.create_connection(("127.0.0.1", tg.server_address[1]))
                c.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                def pump(a, b):
                    try:
                        while True:
                            d = a.recv(4096)
                            if not d: break
                            b.sendall(d)
                    except OSError: pass
                    finally:
                        try: b.shutdown(socket.SHUT_WR)
                        except OSError: pass
                threading.Thread(target=pump, args=(up, c), daemon=True).start()
                pump(c, up)

        tg = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Tg)
        hp = http.server.ThreadingHTTPServer(("127.0.0.1", 0), HttpProxy)
        sp = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Socks); sp.daemon_threads = True
        for srv in (tg, hp, sp): threading.Thread(target=srv.serve_forever, daemon=True).start()
        old_api, notify.TELEGRAM_API = notify.TELEGRAM_API, "http://api.telegram.test:80"
        tok = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
        try:
            a = admin()
            put = lambda d: a.put("/settings/notify", json=d, headers=H)
            base = {"telegram_token": tok, "telegram_chat": "-100500"}
            self.assertEqual(put(dict(base, telegram_proxy_type="ftp")).status_code, 400)
            self.assertEqual(put(dict(base, telegram_proxy_type="http", telegram_proxy_host="")).status_code, 400)
            self.assertEqual(put(dict(base, telegram_proxy_type="http", telegram_proxy_host="http://x", telegram_proxy_port=1)).status_code, 400)
            self.assertEqual(put(dict(base, telegram_proxy_type="http", telegram_proxy_host="x", telegram_proxy_port=70000)).status_code, 400)
            self.assertEqual(put(dict(base, telegram_proxy_type="http", telegram_proxy_host="x", telegram_proxy_port=1,
                                      telegram_proxy_password="p")).status_code, 400)           # пароль без логина
            test = lambda cfg: a.post("/settings/notify/test", json={"channel": "telegram", "config": dict(base, **cfg)}, headers=H).get_json()
            # без прокси: запрос идёт на api.telegram.test — не резолвится, ошибка без токена
            r = test({"telegram_proxy_type": "none"})
            self.assertFalse(r["ok"]); self.assertNotIn(tok, r["error"])
            # HTTP-прокси с логином/паролем
            r = test({"telegram_proxy_type": "http", "telegram_proxy_host": "127.0.0.1", "telegram_proxy_port": hp.server_address[1],
                      "telegram_proxy_user": "pu", "telegram_proxy_password": "ppw"})
            self.assertTrue(r["ok"], r)
            path, auth = seen["http"][-1]
            self.assertEqual(path, "http://api.telegram.test:80/bot%s/sendMessage" % tok)
            self.assertEqual(auth, "Basic " + base64.b64encode(b"pu:ppw").decode())
            # SOCKS5 с логином/паролем; имя хоста передаётся прокси
            sport = sp.server_address[1]
            r = test({"telegram_proxy_type": "socks5", "telegram_proxy_host": "127.0.0.1", "telegram_proxy_port": sport,
                      "telegram_proxy_user": "pu", "telegram_proxy_password": "ppw"})
            self.assertTrue(r["ok"], r)
            self.assertEqual(seen["socks"][-1], ("api.telegram.test", 80))
            self.assertEqual(seen["tg"][-1], "/bot%s/sendMessage" % tok)
            r = test({"telegram_proxy_type": "socks5", "telegram_proxy_host": "127.0.0.1", "telegram_proxy_port": sport,
                      "telegram_proxy_user": "pu", "telegram_proxy_password": "wrong"})
            self.assertFalse(r["ok"]); self.assertIn("логин", r["error"])
            # сохранение: пароль прокси не отдаётся, пустое поле не затирает сохранённый
            r = put(dict(base, telegram_enabled=True, telegram_proxy_type="socks5", telegram_proxy_host="127.0.0.1",
                         telegram_proxy_port=sport, telegram_proxy_user="pu", telegram_proxy_password="ppw"))
            self.assertEqual(r.status_code, 200, r.get_json())
            self.assertTrue(r.get_json()["telegram_proxy_password_set"]); self.assertNotIn("ppw", str(r.get_json()))
            r = test({})                                                                          # берёт сохранённое
            self.assertTrue(r["ok"], r)
            put({"telegram_proxy_host": "localhost"})
            self.assertEqual(config.load("notify")["telegram_proxy_password"], "ppw")
        finally:
            notify.TELEGRAM_API = old_api
            for srv in (tg, hp, sp): srv.shutdown()
            config.save("notify", dict(config.DEFAULTS["notify"]))

    def test_19d_notification_result_text(self):
        import notify
        rt = lambda action, status, res: notify.result_text({"action": action}, status, res)
        orig = mssql_ops.find_backup
        try:
            mssql_ops.find_backup = lambda conn, path: {"size": 10, "compressed_size": 2500}
            self.assertEqual(rt("backup", "ok", "/var/opt/mssql/backup/sales_1.bak"), "sales_1.bak, 3 КБ")
            self.assertEqual(rt("backup", "ok", "\\\\srv\\share\\dir\\a.bak"), "a.bak, 3 КБ")
            self.assertEqual(rt("backup", "ok", "s3://minio:9000/b/sql/x.bak"), "x.bak, 3 КБ")
            mssql_ops.find_backup = lambda conn, path: {"size": 7200000, "compressed_size": 0}
            self.assertEqual(rt("backup", "ok", "/b/c.bak"), "c.bak, 7.2 МБ")
            mssql_ops.find_backup = lambda conn, path: (_ for _ in ()).throw(RuntimeError("нет связи"))
            self.assertEqual(rt("backup", "ok", "/b/c.bak"), "c.bak")                       # размер не узнать — только имя
        finally:
            mssql_ops.find_backup = orig
        # восстановление: путь → имя файла, остальное как есть
        self.assertEqual(rt("restore", "ok", "/var/opt/mssql/backup/sales_1.bak -> sales2 (перезапись)"), "sales_1.bak -> sales2 (перезапись)")
        self.assertEqual(rt("restore", "ok", "s3://h:9000/b/sql/s.bak -> new1 (новая база)"), "s.bak -> new1 (новая база)")
        self.assertEqual(rt("restore", "error", "Cannot open backup device '/var/x/y.bak'. Operating system error 2"),
                         "Cannot open backup device 'y.bak'. Operating system error 2")
        self.assertEqual(rt("backup", "error", "диск полон: /var/x"), "диск полон: /var/x")   # ошибки копии без изменений
        self.assertEqual(notify.fmt_size(2_500_000_000), "2.50 ГБ")

    def test_20_restore(self):
        a = admin()
        path = Fake.backups[0][4]
        lst = a.get("/backups").get_json()["backups"]
        self.assertEqual(lst[0]["path"], path)

        self.assertEqual(a.post("/restore", json={"path": "/nope.bak", "target": "sales"}, headers=H).status_code, 404)
        self.assertEqual(a.post("/restore", json={"path": path, "target": "sales"}, headers=H).status_code, 400)  # нет confirm

        r = a.post("/restore", json={"path": path, "target": "sales", "confirm": "sales", "kick_users": True}, headers=H)
        self.assertEqual(r.status_code, 202)
        self.assertEqual(wait_job(a, r.get_json()["id"])["status"], "ok")
        joined = "\n".join(Fake.sqls)
        self.assertIn("ALTER DATABASE [sales] SET SINGLE_USER WITH ROLLBACK IMMEDIATE", joined)
        self.assertIn("RESTORE DATABASE [sales] FROM DISK = N'%s' WITH REPLACE, RECOVERY, CHECKSUM" % path, joined)
        self.assertIn("ALTER DATABASE [sales] SET MULTI_USER", joined)

        Fake.sqls.clear()
        r = a.post("/restore", json={"path": path, "target": "sales_copy", "new": True}, headers=H)
        self.assertEqual(wait_job(a, r.get_json()["id"])["status"], "ok")
        sql = last_sql("RESTORE DATABASE")
        self.assertIn("MOVE N'sales' TO N'/var/opt/mssql/data/sales_copy_sales.mdf'", sql)
        self.assertIn("MOVE N'sales_log' TO N'/var/opt/mssql/log/sales_copy_sales_log.ldf'", sql)
        self.assertNotIn("REPLACE", sql)

    def test_21_restore_guards(self):
        a = admin()
        path = Fake.backups[0][4]
        post = lambda body: a.post("/restore", json={"path": path, **body}, headers=H)
        r = post({"target": "sales2", "new": True})
        self.assertEqual(r.status_code, 400)
        self.assertIn("уже существует", r.get_json()["error"])
        self.assertEqual(post({"target": "master", "new": True}).status_code, 400)
        self.assertEqual(post({"target": "master", "confirm": "master"}).status_code, 403)   # системной нет в списке
        self.assertEqual(post({"target": "bad\x01name", "new": True}).status_code, 400)
        self.assertEqual(post({"target": "nodb", "confirm": "nodb"}).status_code, 403)       # несуществующая

    def test_22_restore_from_s3_path_creates_credential(self):
        a = admin()
        a.put("/settings/storage", json={"type": "s3", "s3_endpoint": "minio.local", "s3_port": 9000, "s3_bucket": "b",
                                         "s3_access_key": "AKIA", "s3_secret_key": "S", "s3_virtual_host": False}, headers=H)
        url = "s3://minio.local:9000/b/sql/sales_1.bak"
        Fake.backups.append(("sales", datetime.datetime(2026, 10, 21, 3, 0, 0), 1, 1, url, "sa", 102))
        try:
            r = a.post("/restore", json={"path": url, "target": "sales", "confirm": "sales"}, headers=H)
            self.assertEqual(wait_job(a, r.get_json()["id"])["status"], "ok")
            self.assertIn("RESTORE DATABASE [sales] FROM URL = N'%s'" % url, "\n".join(Fake.sqls))
            self.assertIn("CREATE CREDENTIAL", "\n".join(Fake.sqls))
        finally:
            Fake.backups.pop()


    # --- пользователи, группы, права на базы, запросы ---
    def test_30_users_added_on_first_login_and_default_targets(self):
        ldap_on(); reset_access()
        a = admin()
        path = Fake.backups[0][4]
        login("erin", "erinpw")
        names = [u["name"] for u in a.get("/access/users").get_json()["users"]]
        self.assertIn("erin", names)
        self.assertNotIn("admin", names)                      # локальный администратор в список не попадает
        added = a.get("/history?action=user_added&limit=50").get_json()["items"]
        self.assertTrue(any(i["username"] == "erin" for i in added))

        bob = login("bob", "bobpw")[0]
        t = bob.get("/restore/targets").get_json()
        self.assertEqual(t["databases"], [])                  # по умолчанию список пуст
        self.assertTrue(t["needs_approval"])
        t = a.get("/restore/targets").get_json()
        self.assertEqual(t["databases"], ["sales", "sales2"])
        self.assertFalse(t["needs_approval"])
        r = bob.post("/restore", json={"database": "sales", "target": "sales", "confirm": "sales"}, headers=H)
        self.assertEqual(r.status_code, 403)
        self.assertFalse([s for s in Fake.sqls if s.startswith("RESTORE")])

    def test_31_new_db_by_operator_creates_request(self):
        ldap_on(); reset_access()
        path = Fake.backups[0][4]
        bob = login("bob", "bobpw")[0]
        access.set_user("bob", [], [], ["sales"], ["sales"])
        r = bob.post("/restore", json={"database": "sales", "target": "req_db1", "new": True}, headers=H)
        self.assertEqual(r.status_code, 202, r.get_json())
        body = r.get_json()
        self.assertTrue(body["needs_approval"])
        self.assertFalse([s for s in Fake.sqls if s.startswith("RESTORE")])   # без подтверждения ничего не восстановлено
        dup = bob.post("/restore", json={"database": "sales", "target": "req_db1", "new": True}, headers=H)
        self.assertEqual(dup.status_code, 409)
        lst = bob.get("/requests").get_json()
        item = [i for i in lst["items"] if i["id"] == body["request"]][0]
        self.assertEqual((item["status"], item["mine"], item["can_decide"], item["can_cancel"]), ("pending", True, False, True))
        self.assertGreaterEqual(lst["pending"], 1)
        self.assertEqual(login("alice", "alicepw")[0].get("/requests").status_code, 403)   # просмотр: запросов нет
        self.assertEqual(bob.post("/requests/%d/cancel" % body["request"], headers=H).status_code, 200)

    def test_32_approval_by_internal_group(self):
        ldap_on(); reset_access()
        a = admin()
        a.put("/settings/storage", json={"type": "local", "local_path": "/var/opt/mssql/backup"}, headers=H)
        path = Fake.backups[0][4]
        bob, erin = login("bob", "bobpw")[0], login("erin", "erinpw")[0]
        access.set_user("bob", [], [], ["sales"], ["sales"])
        self.assertNotIn("approve", erin.get("/auth/me").get_json()["user"]["perms"])
        rid = bob.post("/restore", json={"database": "sales", "target": "approved_db", "new": True}, headers=H).get_json()["request"]
        self.assertEqual(erin.post("/requests/%d/approve" % rid, json={}, headers=H).status_code, 403)

        gid = a.post("/access/groups", json={"name": "Approvers", "approver": True, "members": ["erin"]},
                     headers=H).get_json()["id"]
        self.assertIn("approve", erin.get("/auth/me").get_json()["user"]["perms"])    # действует сразу
        item = [i for i in erin.get("/requests").get_json()["items"] if i["id"] == rid][0]
        self.assertTrue(item["can_decide"])
        self.assertEqual(bob.post("/requests/%d/approve" % rid, json={}, headers=H).status_code, 403)

        # автор-подтверждающий не может подтвердить собственный запрос
        a.put("/access/groups/%d" % gid, json={"name": "Approvers", "approver": True, "members": ["erin", "bob"]}, headers=H)
        r = bob.post("/requests/%d/approve" % rid, json={}, headers=H)
        self.assertEqual(r.status_code, 403)
        self.assertIn("собственный", r.get_json()["error"])
        a.put("/access/groups/%d" % gid, json={"name": "Approvers", "approver": True, "members": ["erin"]}, headers=H)

        # идёт другая операция: подтверждённый запрос встаёт в очередь следом
        Fake.gate = threading.Event()
        rb = a.post("/backup", json={"database": "sales"}, headers=H)
        self.assertEqual(rb.status_code, 202)
        r = erin.post("/requests/%d/approve" % rid, json={"comment": "ok"}, headers=H)
        self.assertEqual(r.status_code, 202, r.get_json())
        self.assertEqual(r.get_json()["position"], 2)
        self.assertEqual(access.get_request(rid)["status"], "approved")
        self.assertEqual(a.get("/history/%d" % r.get_json()["id"]).get_json()["status"], "queued")
        self.assertFalse([x for x in Fake.sqls if x.startswith("RESTORE DATABASE")])     # пока не выполнялось
        Fake.gate.set()
        wait_job(a, rb.get_json()["id"])
        row = wait_job(a, r.get_json()["id"])
        self.assertEqual(row["status"], "ok", row)
        self.assertEqual(row["username"], "bob")              # выполнено от имени автора запроса
        self.assertIn("erin", row["details"])                 # подтвердил erin
        sql = last_sql("RESTORE DATABASE")
        self.assertIn("RESTORE DATABASE [approved_db]", sql)
        self.assertIn("MOVE N'sales' TO N'/var/opt/mssql/data/approved_db_sales.mdf'", sql)
        self.assertNotIn("REPLACE", sql)
        item = [i for i in erin.get("/requests").get_json()["items"] if i["id"] == rid][0]
        self.assertEqual((item["status"], item["job_status"], item["decided_by"]), ("approved", "ok", "erin"))
        self.assertEqual(erin.post("/requests/%d/approve" % rid, json={}, headers=H).status_code, 409)
        actions = {i["action"] for i in a.get("/history?limit=200").get_json()["items"]}
        self.assertTrue({"request_create", "request_approve"} <= actions)

    def test_33_reject_and_cancel(self):
        ldap_on(); reset_access()
        a = admin()
        path = Fake.backups[0][4]
        bob, erin, frank = login("bob", "bobpw")[0], login("erin", "erinpw")[0], login("frank", "frankpw")[0]
        access.set_user("bob", [], [], ["sales"], ["sales"])
        a.post("/access/groups", json={"name": "Approvers", "approver": True, "members": ["erin"]}, headers=H)
        ask = lambda name: bob.post("/restore", json={"database": "sales", "target": name, "new": True}, headers=H).get_json()["request"]

        r1 = ask("rej_db")
        self.assertEqual(erin.post("/requests/%d/reject" % r1, json={"comment": "не нужно"}, headers=H).status_code, 200)
        req = access.get_request(r1)
        self.assertEqual((req["status"], req["comment"], req["decided_by"]), ("rejected", "не нужно", "erin"))
        self.assertEqual(erin.post("/requests/%d/approve" % r1, json={}, headers=H).status_code, 409)

        r2 = ask("can_db")
        self.assertEqual(frank.post("/requests/%d/cancel" % r2, headers=H).status_code, 403)   # чужой запрос
        self.assertEqual(bob.post("/requests/%d/cancel" % r2, headers=H).status_code, 200)
        self.assertEqual(bob.post("/requests/%d/cancel" % r2, headers=H).status_code, 409)
        self.assertEqual(erin.post("/requests/%d/approve" % r2, json={}, headers=H).status_code, 409)
        self.assertFalse([s for s in Fake.sqls if s.startswith("RESTORE")])

    def test_34_overwrite_rights_from_user_and_group(self):
        ldap_on(); reset_access()
        a = admin()
        path = Fake.backups[0][4]
        bob = login("bob", "bobpw")[0]
        targets = lambda: bob.get("/restore/targets").get_json()["databases"]
        self.assertEqual(targets(), [])
        self.assertEqual(a.put("/access/users/bob", json={"allowed_dbs": ["sales2"], "backup_dbs": ["sales", "sales2", "model"], "source_dbs": ["sales", "sales2", "model"], "groups": []}, headers=H).status_code, 200)
        self.assertEqual(targets(), ["sales2"])
        post = lambda body: bob.post("/restore", json={"database": "sales", **body}, headers=H)
        self.assertEqual(post({"target": "sales", "confirm": "sales"}).status_code, 403)   # не отмечена
        self.assertEqual(post({"target": "sales2"}).status_code, 400)                      # нет подтверждения имени

        r = post({"target": "sales2", "confirm": "sales2", "kick_users": True})
        self.assertEqual(r.status_code, 202, r.get_json())
        self.assertEqual(wait_job(bob, r.get_json()["id"])["status"], "ok")
        sql = last_sql("RESTORE DATABASE")
        self.assertIn("MOVE N'sales' TO N'/data/sales2.mdf'", sql)            # файлы копии — на файлы целевой базы
        self.assertIn("MOVE N'sales_log' TO N'/log/sales2_log.ldf'", sql)
        self.assertIn("REPLACE", sql)
        joined = "\n".join(Fake.sqls)
        self.assertIn("ALTER DATABASE [sales2] SET SINGLE_USER", joined)
        self.assertIn("ALTER DATABASE [sales2] SET MULTI_USER", joined)

        gid = a.post("/access/groups", json={"name": "Sales", "allowed_dbs": ["sales"], "backup_dbs": ["sales", "sales2"], "source_dbs": ["sales", "sales2"], "members": ["bob"]},
                     headers=H).get_json()["id"]
        self.assertEqual(sorted(targets()), ["sales", "sales2"])             # личные + групповые
        a.delete("/access/groups/%d" % gid, headers=H)
        self.assertEqual(targets(), ["sales2"])
        a.put("/access/users/bob", json={"allowed_dbs": ["master", "sales"], "backup_dbs": ["sales", "sales2", "model"], "source_dbs": ["sales", "sales2", "model"], "groups": []}, headers=H)
        self.assertEqual(targets(), ["sales"])                                # системные отбрасываются

    def test_35_full_role_creates_new_db_without_approval(self):
        a = admin()
        path = Fake.backups[0][4]
        r = a.post("/restore", json={"path": path, "target": "brandnew", "new": True}, headers=H)
        self.assertEqual(r.status_code, 202)
        self.assertIn("id", r.get_json())
        self.assertNotIn("request", r.get_json())
        self.assertEqual(wait_job(a, r.get_json()["id"])["status"], "ok")
        self.assertIn("RESTORE DATABASE [brandnew]", last_sql("RESTORE DATABASE"))

    def test_36_access_api_validation_and_rights(self):
        ldap_on(); reset_access()
        a = admin()
        bob = login("bob", "bobpw")[0]
        login("frank", "frankpw")
        for url in ("/access/users", "/access/groups"):
            self.assertEqual(bob.get(url).status_code, 403)
        post = lambda body: a.post("/access/groups", json=body, headers=H)
        self.assertEqual(post({"name": ""}).status_code, 400)
        r = post({"name": "G1", "members": ["ghost"]})
        self.assertEqual(r.status_code, 400)
        self.assertIn("ещё не входил", r.get_json()["error"])
        self.assertEqual(post({"name": "G1", "members": ["bob"], "allowed_dbs": ["sales"]}).status_code, 201)
        self.assertEqual(post({"name": "g1"}).status_code, 400)               # дубликат без учёта регистра
        self.assertEqual(post({"name": "G2", "allowed_dbs": "x"}).status_code, 400)
        self.assertEqual(post({"name": "G2", "allowed_dbs": ["a" * 200]}).status_code, 400)
        self.assertEqual(a.put("/access/users/ghost", json={"allowed_dbs": []}, headers=H).status_code, 404)
        self.assertEqual(a.put("/access/users/bob", json={"groups": [9999]}, headers=H).status_code, 400)
        self.assertEqual(a.put("/access/groups/9999", json={"name": "X"}, headers=H).status_code, 404)
        self.assertEqual(a.delete("/access/groups/9999", headers=H).status_code, 404)
        users = {u["name"]: u for u in a.get("/access/users").get_json()["users"]}
        self.assertEqual(len(users["bob"]["groups"]), 1)
        self.assertEqual(a.delete("/access/users/frank", headers=H).status_code, 200)
        self.assertNotIn("frank", [u["name"] for u in a.get("/access/users").get_json()["users"]])
        login("frank", "frankpw")                                              # вернётся при следующем входе
        self.assertIn("frank", [u["name"] for u in a.get("/access/users").get_json()["users"]])

    def test_37_protected_databases_need_admin_approval(self):
        ldap_on(); reset_access()
        a = admin()
        a.put("/settings/storage", json={"type": "local", "local_path": "/var/opt/mssql/backup"}, headers=H)
        path = Fake.backups[0][4]
        bob, erin = login("bob", "bobpw")[0], login("erin", "erinpw")[0]
        # erin — подтверждающая группа (но не администратор); bob может перезаписывать sales и sales2
        a.post("/access/groups", json={"name": "Approvers", "approver": True, "members": ["erin"]}, headers=H)
        a.put("/access/users/bob", json={"allowed_dbs": ["sales", "sales2"], "backup_dbs": ["sales", "sales2", "model"], "source_dbs": ["sales", "sales2", "model"], "groups": []}, headers=H)

        # настройка защиты — только администратору; системные базы отбрасываются
        self.assertEqual(bob.get("/access/protected").status_code, 403)
        self.assertEqual(bob.put("/access/protected", json={"databases": ["sales2"]}, headers=H).status_code, 403)
        self.assertEqual(a.put("/access/protected", json={"databases": "x"}, headers=H).status_code, 400)
        r = a.put("/access/protected", json={"databases": ["sales2", "master"]}, headers=H)
        self.assertEqual(r.get_json()["databases"], ["sales2"])
        self.assertEqual(a.get("/access/protected").get_json()["databases"], ["sales2"])

        t = bob.get("/restore/targets").get_json()
        self.assertEqual((sorted(t["databases"]), t["protected"]), (["sales", "sales2"], ["sales2"]))
        self.assertEqual(a.get("/restore/targets").get_json()["protected"], [])      # администратору ограничений нет

        # обычная база — сразу, защищённая — запросом, ничего не выполняется
        r = bob.post("/restore", json={"database": "sales", "target": "sales", "confirm": "sales"}, headers=H)
        self.assertEqual(wait_job(bob, r.get_json()["id"])["status"], "ok")
        Fake.sqls.clear()
        body = {"database": "sales", "target": "sales2", "confirm": "sales2", "kick_users": True}
        self.assertEqual(bob.post("/restore", json={**body, "confirm": "x"}, headers=H).status_code, 400)
        r = bob.post("/restore", json=body, headers=H)
        self.assertEqual(r.status_code, 202, r.get_json())
        self.assertEqual((r.get_json()["kind"], r.get_json()["needs_approval"]), ("overwrite", True))
        rid = r.get_json()["request"]
        self.assertFalse([x for x in Fake.sqls if x.startswith("RESTORE DATABASE")])
        self.assertEqual(bob.post("/restore", json=body, headers=H).status_code, 409)   # дубликат

        # подтверждающий из группы такой запрос видит, но решить не может; счётчик его не включает
        lst = erin.get("/requests").get_json()
        item = [i for i in lst["items"] if i["id"] == rid][0]
        self.assertEqual((item["kind"], item["can_decide"]), ("overwrite", False))
        self.assertEqual(lst["pending"], 0)
        r = erin.post("/requests/%d/approve" % rid, json={}, headers=H)
        self.assertEqual(r.status_code, 403)
        self.assertIn("администратор", r.get_json()["error"])
        self.assertEqual(access.get_request(rid)["status"], "pending")
        self.assertEqual(erin.post("/requests/%d/reject" % rid, json={}, headers=H).status_code, 403)   # отклонять тоже нельзя
        self.assertEqual(access.get_request(rid)["status"], "pending")

        # администратор подтверждает: перезапись с параметрами из запроса (kick_users)
        item = [i for i in a.get("/requests").get_json()["items"] if i["id"] == rid][0]
        self.assertTrue(item["can_decide"])
        r = a.post("/requests/%d/approve" % rid, json={}, headers=H)
        self.assertEqual(r.status_code, 202, r.get_json())
        row = wait_job(a, r.get_json()["id"])
        self.assertEqual((row["status"], row["username"]), ("ok", "bob"))
        self.assertIn("admin", row["details"])
        sql = last_sql("RESTORE DATABASE")
        self.assertIn("RESTORE DATABASE [sales2]", sql)
        self.assertIn("MOVE N'sales' TO N'/data/sales2.mdf'", sql)
        self.assertIn("REPLACE", sql)
        self.assertIn("ALTER DATABASE [sales2] SET SINGLE_USER", "\n".join(Fake.sqls))

        # администратор защищённую базу восстанавливает сразу, защиту можно снять
        r = a.post("/restore", json={"path": path, "target": "sales2", "confirm": "sales2"}, headers=H)
        self.assertIn("id", r.get_json())
        wait_job(a, r.get_json()["id"])
        a.put("/access/protected", json={"databases": []}, headers=H)
        r = bob.post("/restore", json={"database": "sales", "target": "sales2", "confirm": "sales2"}, headers=H)
        self.assertIn("id", r.get_json())
        wait_job(bob, r.get_json()["id"])

    def test_38_overwrite_request_cancel_and_migration(self):
        ldap_on(); reset_access()
        a = admin()
        path = Fake.backups[0][4]
        bob = login("bob", "bobpw")[0]
        a.put("/access/users/bob", json={"allowed_dbs": ["sales"], "backup_dbs": ["sales", "sales2", "model"], "source_dbs": ["sales", "sales2", "model"], "groups": []}, headers=H)
        a.put("/access/protected", json={"databases": ["sales"]}, headers=H)
        rid = bob.post("/restore", json={"database": "sales", "target": "sales", "confirm": "sales"}, headers=H).get_json()["request"]
        self.assertEqual(bob.post("/requests/%d/cancel" % rid, headers=H).status_code, 200)
        self.assertEqual(a.post("/requests/%d/approve" % rid, json={}, headers=H).status_code, 409)
        self.assertFalse([x for x in Fake.sqls if x.startswith("RESTORE DATABASE")])
        a.put("/access/protected", json={"databases": []}, headers=H)

        # база от прошлой версии (таблица requests без колонок kind/kick) дополняется при первом обращении
        import sqlite3, subprocess
        old = tempfile.mkdtemp()
        con = sqlite3.connect(os.path.join(old, "history.db"))
        con.executescript(
            "CREATE TABLE requests (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, requester TEXT NOT NULL, "
            "requester_name TEXT NOT NULL, requester_source TEXT, requester_role TEXT, path TEXT NOT NULL, "
            "source_db TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', "
            "decided_by TEXT NOT NULL DEFAULT '', decided_ts TEXT, comment TEXT NOT NULL DEFAULT '', job_id INTEGER);"
            "INSERT INTO requests (ts, requester, requester_name, path, source_db, target) "
            "VALUES ('2026-10-01T00:00:00Z', 'bob', 'bob', '/x.bak', 'sales', 'old_db');")
        con.commit(); con.close()
        code = ("import sys; sys.path.insert(0, %r); import access; "
                "r = access.list_requests(); print(r[0]['kind'], r[0]['kick'], r[0]['target'])"
                % os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
        out = subprocess.run([sys.executable, "-I", "-c", code], env={**os.environ, "DATA_DIR": old},
                             capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "create 0 old_db", out.stderr)

    def test_39_history_migration_adds_queue_params(self):
        import sqlite3, subprocess
        old = tempfile.mkdtemp()
        con = sqlite3.connect(os.path.join(old, "history.db"))
        con.executescript(
            "CREATE TABLE history (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, finished TEXT, "
            "username TEXT NOT NULL, source TEXT NOT NULL DEFAULT '', role TEXT NOT NULL DEFAULT '', "
            "ip TEXT NOT NULL DEFAULT '', action TEXT NOT NULL, target TEXT NOT NULL DEFAULT '', "
            "status TEXT NOT NULL DEFAULT 'ok', details TEXT NOT NULL DEFAULT '');"
            "INSERT INTO history (ts, username, action) VALUES ('2026-10-01T00:00:00Z', 'bob', 'login');")
        con.commit(); con.close()
        code = ("import sys; sys.path.insert(0, %r); import history; "
                "i = history.enqueue({'name': 'bob'}, 'backup', 'sales', {'database': 'sales'}); "
                "j = history.claim_next(); print(i == j['id'], j['params'], history.position(i))"
                % os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app"))
        out = subprocess.run([sys.executable, "-I", "-c", code], env={**os.environ, "DATA_DIR": old},
                             capture_output=True, text=True)
        self.assertEqual(out.stdout.strip(), "True {'database': 'sales'} 1", out.stderr)

    # --- история ---
    def test_40_independent_backup_source_restore_access(self):
        ldap_on(); reset_access()
        a = admin()
        bob = login("bob", "bobpw")[0]
        alice = login("alice", "alicepw")[0]
        Fake.existing.update({"hr", "crm"})
        names = lambda c, url, key: [x if isinstance(x, str) else x["database"] for x in c.get(url).get_json()[key]]
        Fake.backups.append(("hr", datetime.datetime(2026, 10, 21, 3, 0, 0), 1, 1, "/b/hr.bak", "sa", 300))
        Fake.backups.append(("crm", datetime.datetime(2026, 10, 21, 4, 0, 0), 1, 1, "/b/crm.bak", "sa", 301))
        try:
            # по умолчанию ничего нет, у администратора — всё
            self.assertEqual(names(bob, "/databases", "databases"), [])
            self.assertEqual(names(bob, "/databases?for=backup", "databases"), [])
            self.assertIn("hr", names(a, "/databases?for=backup", "databases"))
            self.assertEqual(bob.post("/backup", json={"database": "sales"}, headers=H).status_code, 403)
            # три независимых списка: копии — sales2; источники — hr; восстановление в — crm (личный) + sales (группа)
            gid = a.post("/access/groups", json={"name": "V", "backup_dbs": ["sales"], "source_dbs": [], "allowed_dbs": ["sales"],
                                                  "members": ["bob", "alice"]}, headers=H).get_json()["id"]
            a.put("/access/users/bob", json={"backup_dbs": ["sales2"], "source_dbs": ["hr"], "allowed_dbs": ["crm"], "groups": [gid]}, headers=H)
            # копии: личные + группа; источники и цели на это не влияют
            self.assertEqual(sorted(names(bob, "/databases?for=backup", "databases")), ["sales", "sales2"])
            self.assertEqual(names(alice, "/databases?for=backup", "databases"), ["sales"])
            r = bob.post("/backup", json={"database": "sales2"}, headers=H)
            self.assertEqual(wait_job(bob, r.get_json()["id"])["status"], "ok")
            self.assertEqual(bob.post("/backup", json={"database": "hr"}, headers=H).status_code, 403)     # hr — только источник
            self.assertEqual(bob.post("/backup", json={"database": "crm"}, headers=H).status_code, 403)    # crm — только цель
            # источники: только hr, даже если копии других баз существуют
            self.assertEqual(names(bob, "/restore/sources", "sources"), ["hr"])
            self.assertEqual(bob.get("/restore/copies?database=hr").status_code, 200)
            self.assertEqual(bob.get("/restore/copies?database=sales").status_code, 403)    # sales — можно копировать, но не брать как источник
            # цели: не зависят от копий/источников
            self.assertEqual(sorted(bob.get("/restore/targets").get_json()["databases"]), ["crm", "sales"])
            r = bob.post("/restore", json={"database": "hr", "target": "crm", "confirm": "crm"}, headers=H)
            self.assertEqual(wait_job(bob, r.get_json()["id"])["status"], "ok")
            self.assertIn("/b/hr.bak", last_sql("RESTORE DATABASE"))
            for body in ({"database": "sales"}, {"copy": 301}, {"database": "hr", "copy": 301}):   # источник не разрешён
                for extra in ({"target": "crm", "confirm": "crm"}, {"target": "newdb", "new": True}):
                    r = bob.post("/restore", json=dict(body, **extra), headers=H)
                    self.assertIn(r.status_code, (403, 404), (body, extra, r.get_json()))
                    self.assertNotEqual(r.status_code, 202)
            self.assertEqual(bob.post("/restore", json={"database": "hr", "target": "hr", "confirm": "hr"}, headers=H).status_code, 403)  # hr — не цель
            # просмотр: общий /databases — объединение трёх списков
            self.assertEqual(sorted(names(bob, "/databases", "databases")), ["crm", "hr", "sales", "sales2"])
            # администратор видит всё
            self.assertIn("crm", names(a, "/restore/targets", "databases"))
            self.assertEqual(sorted(names(a, "/restore/sources", "sources")), ["crm", "hr", "sales"])
            # настройки сохраняются; PUT без списков их не стирает; неверный формат — 400
            user = lambda: [x for x in a.get("/access/users").get_json()["users"] if x["name"] == "bob"][0]
            self.assertEqual((user()["backup_dbs"], user()["source_dbs"]), (["sales2"], ["hr"]))
            a.put("/access/users/bob", json={"allowed_dbs": ["crm"], "groups": [gid]}, headers=H)
            self.assertEqual((user()["backup_dbs"], user()["source_dbs"]), (["sales2"], ["hr"]))
            g = a.get("/access/groups").get_json()["groups"][0]
            self.assertEqual((g["backup_dbs"], g["source_dbs"]), (["sales"], []))
            self.assertEqual(a.put("/access/users/bob", json={"backup_dbs": "x"}, headers=H).status_code, 400)
            self.assertEqual(a.put("/access/users/bob", json={"source_dbs": "x"}, headers=H).status_code, 400)
        finally:
            Fake.backups.pop(); Fake.backups.pop()
            Fake.existing.difference_update({"hr", "crm"})

    def test_41_access_lists_migration(self):
        # старая схема без backup_dbs/source_dbs: после миграции оба списка берутся из разрешённых для восстановления баз
        db = access._db()
        db.executescript("""CREATE TABLE users_old AS SELECT name, display, source, role, dn, first_login, last_login, allowed_dbs FROM users;
                            DROP TABLE users; ALTER TABLE users_old RENAME TO users;""")
        db.execute("UPDATE users SET allowed_dbs='[\"sales\"]' WHERE name='bob'"); db.commit()
        access._ready = False
        self.assertEqual((access.scope_dbs("bob", "backup"), access.scope_dbs("bob", "source")), ({"sales"}, {"sales"}))
        reset_access()

    def test_42_recent_jobs_scope_filters_and_short_paths(self):
        # изолируем: убираем прежние задачи из общей истории на время теста и возвращаем после
        with history.lock:
            db = history.conn()
            saved = db.execute("SELECT * FROM history WHERE action IN ('backup','restore')").fetchall()
            db.execute("DELETE FROM history WHERE action IN ('backup','restore')"); db.commit()
        try:
            self._recent_jobs_body()
        finally:
            with history.lock:
                db = history.conn()
                db.execute("DELETE FROM history WHERE action IN ('backup','restore')")
                db.executemany("INSERT INTO history VALUES (%s)" % ",".join("?" * len(saved[0])), saved) if saved else None
                db.commit()

    def _recent_jobs_body(self):
        ldap_on(); reset_access()
        a = admin()
        a.put("/settings/storage", json={"type": "local", "local_path": "/var/opt/mssql/backup"}, headers=H)
        bob, erin = login("bob", "bobpw")[0], login("erin", "erinpw")[0]
        access.set_user("bob", [], [], ["sales"], ["sales"]); access.set_user("erin", [], [], ["sales2"], [])
        ids = {}
        for who, c, db in (("admin", a, "sales"), ("bob", bob, "sales"), ("erin", erin, "sales2")):
            ids[who] = c.post("/backup", json={"database": db}, headers=H).get_json()["id"]
            wait_job(c, ids[who])
        path = Fake.backups[0][4]
        r = a.post("/restore", json={"path": path, "target": "sales", "confirm": "sales"}, headers=H)
        ids["restore"] = r.get_json()["id"]; wait_job(a, ids["restore"])
        rec = lambda c, q="": c.get("/queue/recent" + q).get_json()
        # область: админ — все, остальные — только свои
        self.assertEqual({i["username"] for i in rec(a)["items"]}, {"admin", "bob", "erin"})
        self.assertEqual(len(rec(a)["items"]), 4)
        self.assertEqual([i["id"] for i in rec(bob)["items"]], [ids["bob"]])
        self.assertEqual([i["id"] for i in rec(erin)["items"]], [ids["erin"]])
        self.assertEqual([i["id"] for i in rec(bob, "?user=admin")["items"]], [ids["bob"]])     # чужой фильтр пользователя игнорируется
        # пути: админу полностью, пользователю — сокращённо; в /queue и /queue/recent одинаково
        full = [i for i in rec(a)["items"] if i["id"] == ids["bob"]][0]["details"]
        short = rec(bob)["items"][0]["details"]
        self.assertIn("/var/opt/mssql/backup/", full)
        self.assertNotIn("/var/opt", short); self.assertTrue(short.startswith("…/sales_"), short)
        self.assertNotIn("/var/opt", str(bob.get("/queue").get_json()))
        # поиск по результату не раскрывает скрытую часть пути
        self.assertEqual(rec(bob, "?text=mssql")["items"], [])
        self.assertEqual(len(rec(bob, "?text=sales_")["items"]), 1)
        self.assertEqual(len(rec(a, "?text=mssql")["items"]), 4)
        # фильтры по столбцам
        self.assertEqual([i["id"] for i in rec(a, "?action=restore")["items"]], [ids["restore"]])
        self.assertEqual(len(rec(a, "?action=backup")["items"]), 3)
        self.assertEqual([i["id"] for i in rec(a, "?user=erin")["items"]], [ids["erin"]])
        self.assertEqual(sorted(i["target"] for i in rec(a, "?target=sales2")["items"]), ["sales2"])
        self.assertEqual(rec(a, "?status=error")["items"], [])
        self.assertEqual(len(rec(a, "?status=ok")["items"]), 4)
        self.assertEqual(len(rec(a, "?from=2000-01-01T00:00:00Z")["items"]), 4)
        self.assertEqual(rec(a, "?from=2999-01-01T00:00:00Z")["items"], [])
        self.assertEqual(rec(a, "?to=2000-01-01T00:00:00Z")["items"], [])
        self.assertEqual(a.get("/queue/recent?from=bad").status_code, 400)
        # страницы
        p1 = rec(a, "?limit=3"); p2 = rec(a, "?limit=3&offset=3")
        self.assertEqual((len(p1["items"]), p1["has_more"], len(p2["items"]), p2["has_more"]), (3, True, 1, False))
        self.assertEqual(len(rec(bob, "?limit=1")["items"]), 1)

    def test_43_backups_paging_and_history_access(self):
        ldap_on(); reset_access()
        a = admin()
        bob = login("bob", "bobpw")[0]
        extra = [("db%d" % i, datetime.datetime(2026, 9, 1, 3, 0, 0) + datetime.timedelta(hours=i), 1, 1, "/b/db%d.bak" % i, "sa", 1000 + i)
                 for i in range(120)]
        Fake.backups.extend(extra)
        try:
            r = a.get("/backups").get_json()                                  # по умолчанию 50
            self.assertEqual((len(r["backups"]), r["total"], r["limit"], r["offset"]), (50, 121, 50, 0))
            self.assertEqual(r["backups"][0]["database"], "sales")            # новее всех (2026-10-20)
            p3 = a.get("/backups?limit=50&offset=100").get_json()
            self.assertEqual((len(p3["backups"]), p3["total"]), (21, 121))
            ids = [b["id"] for b in a.get("/backups?limit=10&offset=0").get_json()["backups"]]
            ids += [b["id"] for b in a.get("/backups?limit=10&offset=10").get_json()["backups"]]
            self.assertEqual(len(set(ids)), 20)                               # страницы не пересекаются
            self.assertEqual(len(a.get("/backups?limit=500").get_json()["backups"]), 121)
            self.assertEqual(len(a.get("/backups?limit=100&offset=0").get_json()["backups"]), 100)
            for bad in ("limit=7", "limit=1000", "limit=x", "offset=-1"):
                self.assertEqual(a.get("/backups?" + bad).status_code, 400, bad)
            self.assertEqual(bob.get("/backups").status_code, 403)            # по-прежнему только администратору
        finally:
            del Fake.backups[-120:]
        # история сервера — только полный доступ; свою задачу пользователь видит по номеру (пути сокращены)
        self.assertEqual(bob.get("/history").status_code, 403)
        self.assertEqual(a.get("/history").status_code, 200)
        access.set_user("bob", [], [], ["sales"], ["sales"])
        jid = bob.post("/backup", json={"database": "sales"}, headers=H).get_json()["id"]
        wait_job(bob, jid)
        mine = bob.get("/history/%d" % jid).get_json()
        self.assertEqual(mine["status"], "ok"); self.assertNotIn("/var/opt", str(mine)); self.assertNotIn("ip", mine)
        other = a.post("/backup", json={"database": "sales"}, headers=H).get_json()["id"]
        wait_job(a, other)
        self.assertEqual(bob.get("/history/%d" % other).status_code, 404)     # чужая задача
        login_row = a.get("/history?action=login&limit=1").get_json()["items"][0]["id"]
        self.assertEqual(bob.get("/history/%d" % login_row).status_code, 404)  # не задача — не отдаётся
        self.assertIn("/var/opt", a.get("/history/%d" % jid).get_json()["details"])

    def test_90_history(self):
        a = admin()
        h = a.get("/history?limit=200").get_json()
        for need in ("login", "login_failed", "backup", "restore", "settings_ldap", "settings_storage", "settings_test"):
            self.assertTrue(a.get("/history?action=%s&limit=1" % need).get_json()["items"], need)
        only = a.get("/history?action=backup&limit=200").get_json()["items"]
        self.assertTrue(only and all(i["action"] == "backup" for i in only))
        self.assertTrue(all(i["username"] == "bob" or i["username"] == "admin" for i in only))
        bob = a.get("/history?user=bo&limit=200").get_json()["items"]
        self.assertTrue(bob and all("bo" in i["username"] for i in bob))
        page = a.get("/history?limit=1").get_json()
        self.assertEqual((len(page["items"]), page["has_more"]), (1, True))
        self.assertEqual(a.get("/history/999999").status_code, 404)
        failed = a.get("/history?action=login_failed&limit=200").get_json()["items"]
        self.assertNotIn("alicepw", str(h) + str(failed))
        self.assertTrue(failed)

    def test_91_interrupted_on_startup(self):
        hid = history.add({"name": "x", "source": "local", "role": "full"}, "backup", "db", "running", "", "1.1.1.1")
        history.startup()
        self.assertEqual(history.get(hid)["status"], "interrupted")

    def test_92_logout(self):
        c = admin()
        self.assertEqual(c.post("/auth/logout", headers=H).status_code, 200)
        self.assertEqual(c.get("/databases", headers=H).status_code, 401)

    def test_93_default_deny_unknown_endpoint_perm(self):
        # эндпоинт без записи в PERMS недоступен даже администратору
        self.assertEqual(admin().get("/_probe").status_code, 403)


# ---------- HTTPS-сертификат: запрос в доменный CA и установка ----------
import shutil  # noqa: E402
import subprocess  # noqa: E402
import tls  # noqa: E402

APPLY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "deploy", "apply-tls.py")


def sh(*args, data=None):
    p = subprocess.run(args, input=data, capture_output=True)
    assert p.returncode == 0, (args, p.stderr.decode())
    return p.stdout


class TestCA:
    """Мини-центр сертификации на openssl: корневой → промежуточный → выдаёт сертификат по CSR (как AD CS)."""

    def __init__(self, root):
        self.dir = root
        os.makedirs(root, exist_ok=True)
        j = lambda n: os.path.join(root, n)
        self.j = j
        sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", j("root.key"), "-out", j("root.pem"),
           "-subj", "/CN=Test Root CA", "-days", "3650", "-addext", "basicConstraints=critical,CA:TRUE")
        sh("openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes", "-keyout", j("int.key"), "-out", j("int.csr"),
           "-subj", "/CN=Test Issuing CA")
        with open(j("ext_ca.cnf"), "w") as f:
            f.write("basicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,cRLSign\n")
        sh("openssl", "x509", "-req", "-in", j("int.csr"), "-CA", j("root.pem"), "-CAkey", j("root.key"), "-CAcreateserial",
           "-out", j("int.pem"), "-days", "1825", "-extfile", j("ext_ca.cnf"))
        # конфигурация `openssl ca` — нужна, чтобы выпустить сертификат с датами в прошлом (проверка «истёк»)
        os.makedirs(j("db"), exist_ok=True)
        open(j("db/index.txt"), "w").close()
        open(j("db/serial"), "w").write("1000\n")
        with open(j("ca.cnf"), "w") as f:
            f.write("[ca]\ndefault_ca=c\n[c]\ndir=%s\ndatabase=%s/db/index.txt\nserial=%s/db/serial\nnew_certs_dir=%s/db\n"
                    "certificate=%s\nprivate_key=%s\ndefault_md=sha256\npolicy=p\ncopy_extensions=copy\nunique_subject=no\n"
                    "[p]\ncommonName=supplied\n" % (root, root, root, root, j("int.pem"), j("int.key")))

    def issue(self, csr_pem, **kw):
        j = self.j
        open(j("req.csr"), "wb").write(csr_pem)
        args = ["openssl", "ca", "-batch", "-config", j("ca.cnf"), "-in", j("req.csr"), "-out", j("leaf.pem"), "-notext"]
        if kw.get("expired"):
            args += ["-startdate", "20200101000000Z", "-enddate", "20200102000000Z"]
        else:
            args += ["-days", "365"]
        sh(*args)
        return open(j("leaf.pem"), "rb").read()

    def pem(self, name):
        return open(self.j(name), "rb").read()


def to_der(pem):
    return sh("openssl", "x509", "-outform", "DER", data=pem)


class TlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca = TestCA(os.path.join(TMP, "ca"))

    def setUp(self):
        tls.cancel_pending()
        for n in ("request.json", "request.done.json", "status.json", "server.crt", "server.key"):
            try:
                os.unlink(os.path.join(tls.TLS_DIR, n))
            except FileNotFoundError:
                pass

    def _csr(self, c=None, **kw):
        body = dict(cn="Backup.Corp.Local", sans="backup, 10.0.0.5, backup.corp.local", org="Corp", country="ru", key_bits=2048)
        body.update(kw)
        r = (c or admin()).post("/settings/tls/csr", json=body, headers=H)
        return r

    def test_01_create_csr(self):
        a = admin()
        r = self._csr(a)
        self.assertEqual(r.status_code, 201, r.get_json())
        p = r.get_json()["pending"]
        self.assertEqual(p["cn"], "backup.corp.local")
        self.assertEqual(p["sans"], ["DNS:backup.corp.local", "DNS:backup", "IP:10.0.0.5"])       # CN первым, без дублей
        self.assertIn("BEGIN CERTIFICATE REQUEST", p["csr"]); self.assertNotIn("PRIVATE", p["csr"])
        text = sh("openssl", "req", "-noout", "-text", data=p["csr"].encode()).decode()
        for need in ("DNS:backup.corp.local", "DNS:backup", "IP Address:10.0.0.5", "TLS Web Server Authentication", "Public-Key: (2048 bit)",
                     "O = Corp", "C = RU"):
            self.assertIn(need, text)
        self.assertEqual(oct(os.stat(os.path.join(tls.TLS_DIR, "pending.key")).st_mode & 0o777), "0o600")
        dl = a.get("/settings/tls/csr")
        self.assertEqual(dl.status_code, 200); self.assertIn("attachment", dl.headers["Content-Disposition"])
        self.assertEqual(dl.data, p["csr"].encode())
        g = a.get("/settings/tls").get_json()
        self.assertEqual(g["pending"]["cn"], "backup.corp.local"); self.assertNotIn("PRIVATE", str(g))
        self.assertIsNone(g["installed"]); self.assertEqual(g["default_cn"], "localhost")
        self.assertEqual(a.delete("/settings/tls/csr", headers=H).status_code, 200)
        self.assertIsNone(a.get("/settings/tls").get_json()["pending"])
        self.assertEqual(a.get("/settings/tls/csr").status_code, 404)

    def test_02_csr_validation_and_injection(self):
        for bad in ({"cn": ""}, {"cn": "bad name!"}, {"cn": "x" * 70}, {"cn": "a.b", "sans": "evil;rm -rf"},
                    {"cn": "a.b", "sans": "x.y\\nDNS.9=z"}, {"cn": "a.b", "org": "Corp\nCN=evil"}, {"cn": "a.b", "org": "A=B"},
                    {"cn": "a.b", "country": "RUS"}, {"cn": "a.b", "key_bits": 512}, {"cn": "a.b", "key_bits": "x"},
                    {"cn": "a.b", "sans": ",".join("h%d.example.com" % i for i in range(25))}):
            self.assertEqual(self._csr(**bad).status_code, 400, bad)
        self.assertEqual(self._csr(cn="10.1.2.3", sans="").status_code, 201)                   # CN может быть IP
        self.assertEqual(self._csr(cn="srv.corp.local", sans="*.corp.local").status_code, 201)  # wildcard в SAN
        self.assertEqual(self._csr(cn="srv.corp.local", org="ООО Ромашка", key_bits=3072).status_code, 201)

    def test_03_permissions(self):
        ldap_on(); reset_access()
        bob, alice = login("bob", "bobpw")[0], login("alice", "alicepw")[0]
        for c in (bob, alice):
            self.assertEqual(c.get("/settings/tls").status_code, 403)
            self.assertEqual(self._csr(c).status_code, 403)
            self.assertEqual(c.get("/settings/tls/csr").status_code, 403)
            self.assertEqual(c.post("/settings/tls/install", json={"certificate": "x"}, headers=H).status_code, 403)
            self.assertEqual(c.delete("/settings/tls/csr", headers=H).status_code, 403)
        self.assertEqual(admin().post("/settings/tls/csr", json={"cn": "a.b"}).status_code, 403)   # без CSRF-заголовка

    def test_04_install_formats_and_chain(self):
        a = admin()
        ca = self.ca
        leaf = ca.issue(self._csr(a).get_json()["pending"]["csr"].encode())
        inter, root = ca.pem("int.pem"), ca.pem("root.pem")
        cases = {
            "pem-leaf": ({"certificate": leaf.decode()}, 1),
            "pem-bundle-unordered": ({"certificate": (root + inter + leaf).decode()}, 2),        # лист + промежуточный; корень отброшен
            "der": ({"certificate_b64": __import__("base64").b64encode(to_der(leaf)).decode()}, 1),
        }
        p7b = sh("openssl", "crl2pkcs7", "-nocrl", "-certfile", ca.j("int.pem"), "-certfile", ca.j("leaf.pem"))
        cases["pkcs7-pem"] = ({"certificate": p7b.decode()}, 2)
        cases["pkcs7-der"] = ({"certificate_b64": __import__("base64").b64encode(sh("openssl", "pkcs7", "-outform", "DER", data=p7b)).decode()}, 2)
        for name, (body, n) in cases.items():
            r = a.post("/settings/tls/install", json=dict(body, https_port=8443, redirect_http=False), headers=H)
            self.assertEqual(r.status_code, 202, (name, r.get_json()))
            res = r.get_json()
            self.assertEqual(res["chain_length"], n, name)
            self.assertEqual(res["certificate"]["cn"], "backup.corp.local")
            self.assertIn("backup", res["certificate"]["sans"]); self.assertIn("10.0.0.5", res["certificate"]["sans"])
            self.assertFalse(res["certificate"]["expired"]); self.assertEqual(res["warnings"], [])
            req = json.load(open(os.path.join(tls.TLS_DIR, "request.json")))
            self.assertEqual((req["id"], req["https_port"], req["redirect_http"], req["by"]), (res["id"], 8443, False, "admin"))
            crt = open(os.path.join(tls.TLS_DIR, "server.crt"), "rb").read()
            self.assertEqual(crt.count(b"BEGIN CERTIFICATE"), n)
            self.assertEqual(oct(os.stat(os.path.join(tls.TLS_DIR, "server.key")).st_mode & 0o777), "0o600")
            self.assertEqual(a.get("/settings/tls").get_json()["waiting"]["id"], res["id"])
        self.assertIn("settings_tls", {i["action"] for i in a.get("/history?action=settings_tls&limit=50").get_json()["items"]})
        self.assertNotIn("PRIVATE", str(a.get("/history?limit=50").get_json()))

    def test_05_install_rejections(self):
        a = admin()
        ca = self.ca
        post = lambda body: a.post("/settings/tls/install", json=body, headers=H)
        self.assertEqual(post({"certificate": "x"}).status_code, 400)                       # нет запроса
        csr = self._csr(a).get_json()["pending"]["csr"].encode()
        good = ca.issue(csr)
        self.assertEqual(post({"certificate": ""}).status_code, 400)
        self.assertEqual(post({"certificate": "мусор"}).status_code, 400)
        self.assertEqual(post({"certificate_b64": "AAAA"}).status_code, 400)
        self.assertEqual(post({"certificate": good.decode(), "https_port": 0}).status_code, 400)
        self.assertEqual(post({"certificate": good.decode(), "https_port": "x"}).status_code, 400)
        # чужой сертификат (другой ключ)
        other = os.path.join(TMP, "other"); os.makedirs(other, exist_ok=True)
        sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", other + "/k.pem", "-out", other + "/c.pem", "-subj", "/CN=other", "-days", "5")
        r = post({"certificate": open(other + "/c.pem").read()})
        self.assertEqual(r.status_code, 400); self.assertIn("не соответствует", r.get_json()["error"])
        # закрытый ключ вместо сертификата
        r = post({"certificate": open(other + "/k.pem").read()})
        self.assertEqual(r.status_code, 400); self.assertIn("закрытый ключ", r.get_json()["error"])
        # истёк срок
        expired = ca.issue(csr, expired=True)
        r = post({"certificate": expired.decode()})
        self.assertEqual(r.status_code, 400); self.assertIn("истёк", r.get_json()["error"])
        self.assertFalse(os.path.exists(os.path.join(tls.TLS_DIR, "request.json")))        # ничего не передано на применение
        # имя не совпало с запросом — установка идёт, но с предупреждением
        sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", other + "/k2.pem", "-out", other + "/c2.pem",
           "-subj", "/CN=unrelated.example", "-days", "5")
        key = open(os.path.join(tls.TLS_DIR, "pending.key"), "rb").read()
        sh("openssl", "req", "-x509", "-key", os.path.join(tls.TLS_DIR, "pending.key"), "-out", other + "/c3.pem", "-subj", "/CN=unrelated.example", "-days", "5")
        r = post({"certificate": open(other + "/c3.pem").read()})
        self.assertEqual(r.status_code, 202, r.get_json()); self.assertTrue(r.get_json()["warnings"])
        self.assertEqual(open(os.path.join(tls.TLS_DIR, "pending.key"), "rb").read(), key)   # прежний запрос не затронут

    def test_06_secure_cookie_via_forwarded_proto(self):
        c = webapp.app.test_client()
        r = c.post("/auth/login", json={"username": "admin", "password": "adminpw"}, headers=H)
        self.assertNotIn("Secure", r.headers.get("Set-Cookie", ""))
        c = webapp.app.test_client()
        r = c.post("/auth/login", json={"username": "admin", "password": "adminpw"}, headers=dict(H, **{"X-Forwarded-Proto": "https"}))
        self.assertIn("Secure", r.headers.get("Set-Cookie", ""))
        self.assertTrue(c.get("/settings/tls", headers={"X-Forwarded-Proto": "https"}).get_json()["secure"])

    # --- скрипт применения (deploy/apply-tls.py) с заглушками nginx/systemctl ---
    def _env(self, nginx_ok=True):
        root = os.path.join(TMP, "apply_%d" % time.time_ns())
        d = {n: os.path.join(root, n) for n in ("state", "ssl", "etc", "bin")}
        for v in d.values():
            os.makedirs(v)
        conf_dir = os.path.join(root, "nginx"); os.makedirs(conf_dir)
        log = os.path.join(root, "calls.log")
        stub = lambda name, body: (open(os.path.join(d["bin"], name), "w").write("#!/bin/sh\n" + body), os.chmod(os.path.join(d["bin"], name), 0o755))
        stub("nginx", 'echo "nginx $@" >> %s\n%s' % (log, "exit 0" if nginx_ok else 'echo "emerg: bad config" >&2; exit 1'))
        stub("systemctl", 'echo "systemctl $@" >> %s\nexit 0' % log)
        env = dict(os.environ, TLS_STATE_DIR=d["state"], TLS_SSL_DIR=d["ssl"], TLS_ETC_DIR=d["etc"],
                   TLS_NGINX_CONF=os.path.join(conf_dir, "mssql-backup.conf"), TLS_NGINX_INC="/etc/nginx/mssql-backup-locations.inc",
                   TLS_NGINX_BIN=os.path.join(d["bin"], "nginx"), TLS_SYSTEMCTL_BIN=os.path.join(d["bin"], "systemctl"))
        open(os.path.join(d["etc"], "web.port"), "w").write("8080\n")
        return d, env, env["TLS_NGINX_CONF"], log

    def _stage(self, d, redirect=True, port=443, leaf_cn=True):
        """Готовит каталог состояния так, как это делает служба: server.crt/key + request.json."""
        a = admin()
        leaf = self.ca.issue(self._csr(a).get_json()["pending"]["csr"].encode())
        r = a.post("/settings/tls/install", json={"certificate": (self.ca.pem("int.pem") + leaf).decode(), "https_port": port,
                                                  "redirect_http": redirect}, headers=H)
        self.assertEqual(r.status_code, 202, r.get_json())
        for n in ("server.crt", "server.key", "request.json", "pending.key", "pending.csr", "pending.json"):
            shutil.copy(os.path.join(tls.TLS_DIR, n), os.path.join(d["state"], n))
        return r.get_json()["id"]

    def _run(self, env, *args):
        return subprocess.run([sys.executable, APPLY] + list(args), env=env, capture_output=True, text=True)

    def test_10_apply_success_with_redirect(self):
        d, env, conf, log = self._env()
        rid = self._stage(d, redirect=True, port=443)
        p = self._run(env)
        self.assertEqual(p.returncode, 0, p.stderr)
        st = json.load(open(os.path.join(d["state"], "status.json")))
        self.assertTrue(st["ok"], st); self.assertEqual(st["id"], rid)
        text = open(conf).read()
        self.assertIn("listen 8080;", text); self.assertIn("listen 443 ssl;", text)
        self.assertIn("return 301 https://$host$request_uri;", text)
        self.assertIn("ssl_certificate %s/server.crt;" % d["ssl"], text); self.assertIn("TLSv1.2 TLSv1.3", text)
        self.assertEqual(oct(os.stat(d["ssl"] + "/server.key").st_mode & 0o777), "0o600")
        self.assertEqual(open(d["ssl"] + "/server.crt").read().count("BEGIN CERTIFICATE"), 2)         # лист + промежуточный
        self.assertTrue(open(d["ssl"] + "/server.key").read().startswith("-----BEGIN PRIVATE KEY"))
        self.assertEqual(json.load(open(d["etc"] + "/tls.json")), {"https_port": 443, "redirect_http": True})
        for n in ("server.crt", "server.key", "pending.key", "pending.csr", "pending.json", "request.json"):
            self.assertFalse(os.path.exists(os.path.join(d["state"], n)), n)                         # ключ в каталоге службы не остаётся
        self.assertTrue(os.path.exists(d["state"] + "/request.done.json"))
        calls = open(log).read(); self.assertIn("nginx -t", calls); self.assertIn("systemctl reload nginx", calls)
        self.assertEqual(self._run(env).returncode, 0)                                                # повторный запуск ничего не ломает
        # --render сохраняет HTTPS при обновлении установщиком
        os.unlink(conf)
        self.assertIn("HTTPS", self._run(env, "--render").stdout); self.assertIn("listen 443 ssl;", open(conf).read())

    def test_11_apply_no_redirect_custom_port(self):
        d, env, conf, log = self._env()
        self._stage(d, redirect=False, port=8443)
        self.assertEqual(self._run(env).returncode, 0)
        text = open(conf).read()
        self.assertIn("listen 8443 ssl;", text); self.assertNotIn("return 301", text)
        self.assertEqual(text.count("include /etc/nginx/mssql-backup-locations.inc;"), 2)           # HTTP остаётся рабочим

    def test_12_apply_redirect_to_nonstandard_port(self):
        d, env, conf, log = self._env()
        self._stage(d, redirect=True, port=8443)
        self.assertEqual(self._run(env).returncode, 0)
        self.assertIn("return 301 https://$host:8443$request_uri;", open(conf).read())

    def test_13_apply_rolls_back_on_nginx_failure(self):
        d, env, conf, log = self._env(nginx_ok=False)
        open(conf, "w").write("OLD CONFIG\n")
        open(d["ssl"] + "/server.crt", "w").write("OLD CERT\n")
        rid = self._stage(d)
        p = self._run(env)
        self.assertEqual(p.returncode, 1)
        st = json.load(open(os.path.join(d["state"], "status.json")))
        self.assertFalse(st["ok"]); self.assertIn("nginx -t", st["message"]); self.assertIn("bad config", st["message"]); self.assertEqual(st["id"], rid)
        self.assertEqual(open(conf).read(), "OLD CONFIG\n")                                          # конфигурация возвращена
        self.assertEqual(open(d["ssl"] + "/server.crt").read(), "OLD CERT\n")
        self.assertFalse(os.path.exists(d["ssl"] + "/server.key")); self.assertFalse(os.path.exists(d["etc"] + "/tls.json"))
        self.assertTrue(os.path.exists(d["state"] + "/pending.key"))                                  # можно повторить установку
        # через API статус виден
        shutil.copy(d["state"] + "/status.json", os.path.join(tls.TLS_DIR, "status.json"))
        self.assertFalse(admin().get("/settings/tls").get_json()["apply"]["ok"])

    def test_14_apply_rejects_bad_input(self):
        d, env, conf, log = self._env()
        self._stage(d)
        other = os.path.join(TMP, "other"); os.makedirs(other, exist_ok=True)
        sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", other + "/k9.pem", "-out", other + "/c9.pem", "-subj", "/CN=z", "-days", "5")
        # ключ не от этого сертификата
        shutil.copy(other + "/k9.pem", d["state"] + "/server.key")
        p = self._run(env); self.assertEqual(p.returncode, 1)
        self.assertIn("не соответствует", json.load(open(d["state"] + "/status.json"))["message"])
        self.assertFalse(os.path.exists(conf))
        # request.json — ссылка: читать нельзя
        d2, env2, conf2, _ = self._env()
        self._stage(d2)
        os.unlink(d2["state"] + "/server.key"); os.symlink("/etc/hostname", d2["state"] + "/server.key")
        self.assertEqual(self._run(env2).returncode, 1)
        self.assertFalse(os.path.exists(conf2))
        # мусор вместо запроса
        d3, env3, conf3, _ = self._env()
        open(d3["state"] + "/request.json", "w").write("{не json")
        self.assertEqual(self._run(env3).returncode, 1)
        self.assertFalse(json.load(open(d3["state"] + "/status.json"))["ok"])
        # порт HTTPS совпал с HTTP
        d4, env4, conf4, _ = self._env()
        self._stage(d4, port=8080)
        self.assertEqual(self._run(env4).returncode, 1)
        self.assertIn("совпадает", json.load(open(d4["state"] + "/status.json"))["message"])

    def test_15_render_http_only(self):
        d, env, conf, log = self._env()
        p = self._run(env, "--render")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(open(conf).read().count("listen"), 1); self.assertIn("listen 8080;", open(conf).read())
        # настройки есть, а файлов сертификата нет — остаёмся на HTTP
        open(d["etc"] + "/tls.json", "w").write('{"https_port": 443, "redirect_http": true}')
        self._run(env, "--render"); self.assertNotIn("ssl", open(conf).read())


if __name__ == "__main__":
    print("ldap3: %s" % ("ЗАГЛУШКА" if STUBBED_LDAP3 else "настоящий"))
    unittest.main(verbosity=2)
