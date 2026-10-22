#!/usr/bin/env python3
"""Применение HTTPS-сертификата (запускается от root службой mssql-backup-tls по сигналу из веб-интерфейса).

Режимы:
  apply-tls.py            обработать запрос из <STATE_DIR>/request.json: проверить сертификат и ключ, установить их
                          в /etc/ssl/mssql-backup, перенастроить nginx, проверить `nginx -t`, перезагрузить nginx;
                          при любой ошибке вернуть прежнее состояние; результат записать в <STATE_DIR>/status.json
  apply-tls.py --render   только сформировать конфигурацию nginx (HTTP-only или HTTPS — по сохранённым настройкам);
                          используется install.sh при установке и обновлении

Каталог состояния принадлежит непривилегированной службе, поэтому его содержимое считается недоверенным: файлы
читаются без перехода по ссылкам, ключ и сертификат перепроверяются и перезаписываются через openssl, а в конфигурацию
nginx попадают только фиксированные пути и числовые порты.
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys

STATE_DIR = os.environ.get("TLS_STATE_DIR", "/var/lib/mssql-backup/tls")
SSL_DIR = os.environ.get("TLS_SSL_DIR", "/etc/ssl/mssql-backup")
ETC_DIR = os.environ.get("TLS_ETC_DIR", "/etc/mssql-backup")
CONF = os.environ.get("TLS_NGINX_CONF", "/etc/nginx/conf.d/mssql-backup.conf")
INC = os.environ.get("TLS_NGINX_INC", "/etc/nginx/mssql-backup-locations.inc")
NGINX = os.environ.get("TLS_NGINX_BIN", "nginx")
SYSTEMCTL = os.environ.get("TLS_SYSTEMCTL_BIN", "systemctl")
OPENSSL = os.environ.get("TLS_OPENSSL_BIN", "openssl")
MAX = 200_000
PEM = re.compile(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", re.S)


class Fail(Exception):
    pass


def now():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read_state(name):
    """Читает обычный файл из каталога состояния; ссылки и слишком большие файлы отвергаются."""
    path = os.path.join(STATE_DIR, name)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return None
    except OSError:
        raise Fail("Файл %s недоступен для безопасного чтения" % name)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(f.fileno())
        if not os.path.isfile(path) or st.st_size > MAX:
            raise Fail("Файл %s имеет недопустимый тип или размер" % name)
        return f.read(MAX + 1)


def run(cmd, data=None):
    return subprocess.run(cmd, input=data, capture_output=True, timeout=60)


def openssl(args, data=None):
    p = run([OPENSSL] + args, data)
    if p.returncode != 0:
        raise Fail("openssl: " + (p.stderr.decode("utf-8", "replace").strip().splitlines() or ["ошибка"])[-1])
    return p.stdout


def web_port():
    try:
        with open(os.path.join(ETC_DIR, "web.port")) as f:
            port = int(f.read().strip())
        if 1 <= port <= 65535:
            return port
    except (OSError, ValueError):
        pass
    try:                                                    # запасной вариант: порт из действующей конфигурации
        with open(CONF) as f:
            m = re.search(r"^\s*listen\s+(\d+)\s*;", f.read(), re.M)
        if m:
            return int(m.group(1))
    except OSError:
        pass
    return 8080


def load_settings():
    try:
        with open(os.path.join(ETC_DIR, "tls.json")) as f:
            d = json.load(f)
        return {"https_port": int(d["https_port"]), "redirect_http": bool(d["redirect_http"])}
    except (OSError, ValueError, KeyError, TypeError):
        return None


def render(settings):
    http = web_port()
    if not settings:
        return ("server {\n    listen %d;\n    server_name _;\n    include %s;\n}\n" % (http, INC))
    hp = settings["https_port"]
    if hp == http:
        raise Fail("Порт HTTPS совпадает с портом HTTP (%d)" % http)
    if settings["redirect_http"]:
        target = "https://$host" + ("" if hp == 443 else ":%d" % hp) + "$request_uri"
        plain = "    location / {\n        return 301 %s;\n    }\n" % target
    else:
        plain = "    include %s;\n" % INC
    return ("server {\n    listen %d;\n    server_name _;\n%s}\n\n"
            "server {\n    listen %d ssl;\n    server_name _;\n"
            "    ssl_certificate %s;\n    ssl_certificate_key %s;\n"
            "    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_session_timeout 1d;\n"
            "    ssl_session_cache shared:mssqlbackup_ssl:5m;\n    ssl_prefer_server_ciphers off;\n"
            "    include %s;\n}\n" % (http, plain, hp, os.path.join(SSL_DIR, "server.crt"),
                                      os.path.join(SSL_DIR, "server.key"), INC))


def write_file(path, data, mode):
    tmp = path + ".new"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode())
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def snapshot(path):
    try:
        with open(path, "rb") as f:
            return f.read()
    except OSError:
        return None


def restore(path, data, mode):
    if data is None:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    else:
        write_file(path, data, mode)


def set_status(ok, message, rid="", **extra):
    owner = os.stat(STATE_DIR)
    path = os.path.join(STATE_DIR, "status.json")
    write_file(path, json.dumps(dict(extra, id=rid, ok=ok, message=message, time=now()), ensure_ascii=False), 0o644)
    try:
        os.chown(path, owner.st_uid, owner.st_gid)
    except OSError:
        pass


def nginx_apply():
    t = run([NGINX, "-t"])
    if t.returncode != 0:
        raise Fail("nginx -t: " + (t.stderr.decode("utf-8", "replace").strip().splitlines() or ["ошибка"])[-1])
    r = run([SYSTEMCTL, "reload", "nginx"])
    if r.returncode != 0:
        raise Fail("Не удалось перезагрузить nginx: " + r.stderr.decode("utf-8", "replace").strip()[-200:])


def process_request():
    raw = read_state("request.json")
    if raw is None:
        return 0                                           # нечего делать (например, повторный запуск после переименования)
    rid = ""
    try:
        try:
            req = json.loads(raw)
            rid = str(req["id"])[:64]
            port, redirect = int(req["https_port"]), bool(req["redirect_http"])
            if not 1 <= port <= 65535:
                raise ValueError
        except (ValueError, KeyError, TypeError):
            raise Fail("Некорректный запрос на применение")
        crt, key = read_state("server.crt"), read_state("server.key")
        if crt is None or key is None:
            raise Fail("Нет файлов сертификата или ключа")
        certs = PEM.findall(crt)
        if not certs:
            raise Fail("В файле сертификата нет ни одного сертификата")
        key_pem = openssl(["pkey", "-passin", "pass:"], key)                # проверка и нормализация ключа
        if openssl(["pkey", "-pubout"], key_pem) != openssl(["x509", "-noout", "-pubkey"], certs[0]):
            raise Fail("Сертификат не соответствует закрытому ключу")
        if run([OPENSSL, "x509", "-noout", "-checkend", "0"], certs[0]).returncode != 0:
            raise Fail("Срок действия сертификата истёк")
        fullchain = b"\n".join(c.strip() + b"\n" for c in certs)
        subject = openssl(["x509", "-noout", "-subject", "-nameopt", "RFC2253"], certs[0]).decode().strip()

        os.makedirs(SSL_DIR, mode=0o755, exist_ok=True)
        crt_path, key_path = os.path.join(SSL_DIR, "server.crt"), os.path.join(SSL_DIR, "server.key")
        old = (snapshot(crt_path), snapshot(key_path), snapshot(CONF))
        old_settings = load_settings()
        try:
            write_file(key_path, key_pem, 0o600)
            write_file(crt_path, fullchain, 0o644)
            write_file(CONF, render({"https_port": port, "redirect_http": redirect}), 0o644)
            nginx_apply()
        except Exception:
            restore(crt_path, old[0], 0o644)
            restore(key_path, old[1], 0o600)
            restore(CONF, old[2], 0o644)
            try:
                nginx_apply()
            except Exception:
                pass
            raise
        os.makedirs(ETC_DIR, exist_ok=True)
        write_file(os.path.join(ETC_DIR, "tls.json"), json.dumps({"https_port": port, "redirect_http": redirect}), 0o644)
        for name in ("server.crt", "server.key", "pending.key", "pending.csr", "pending.json"):
            try:
                os.unlink(os.path.join(STATE_DIR, name))
            except FileNotFoundError:
                pass
        set_status(True, "Сертификат установлен, nginx перезагружен", rid, https_port=port, redirect_http=redirect, subject=subject)
        return 0
    except Fail as e:
        set_status(False, str(e), rid)
        return 1
    except Exception as e:                                  # непредвиденная ошибка — тоже сообщаем, а не молчим
        set_status(False, "Непредвиденная ошибка: %s" % e, rid)
        return 1
    finally:
        try:                                               # запрос обработан: переименование снимает его с очереди
            os.replace(os.path.join(STATE_DIR, "request.json"), os.path.join(STATE_DIR, "request.done.json"))
        except OSError:
            pass


def main():
    if "--render" in sys.argv:
        settings = load_settings()
        if settings and not (os.path.isfile(os.path.join(SSL_DIR, "server.crt")) and os.path.isfile(os.path.join(SSL_DIR, "server.key"))):
            settings = None                                # файлов нет — остаёмся на HTTP
        write_file(CONF, render(settings), 0o644)
        print("HTTPS включён (порт %d)" % settings["https_port"] if settings else "HTTP")
        return 0
    return process_request()


if __name__ == "__main__":
    sys.exit(main())
