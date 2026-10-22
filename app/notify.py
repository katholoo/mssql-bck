"""Уведомления о завершении копирования и восстановления: e-mail (SMTP) и webhook."""
import json
import logging
import re
import http.client
import smtplib
import socket
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from email.message import EmailMessage

import config
import history
import mssql_ops

log = logging.getLogger("backup")
TIMEOUT = 15
TELEGRAM_API = "https://api.telegram.org"
SYSTEM = {"name": "система", "source": "notify", "role": ""}
TITLES = {"backup": "Резервная копия", "restore": "Восстановление"}


CHANNELS = (("email", "email_enabled"), ("telegram", "telegram_enabled"),
            ("bitrix24", "bitrix_enabled"), ("webhook", "webhook_enabled"))


def event_key(action, status):
    return "ev_%s_%s" % (action, "ok" if status == "ok" else "error")


_PATH_RE = re.compile(r"s3://[^\s;,]+|\\\\[^\s;,]+|[A-Za-z]:\\[^\s;,]+|(?<![\w:/.])/[^\s;,]+")


def file_name(path):
    """Последняя часть пути (локального, UNC или s3://…)."""
    return re.split(r"[\\/]", str(path).rstrip("\\/"))[-1]


def strip_paths(text):
    """Заменяет пути к файлам в тексте на конечные имена: «/var/x/a.bak -> db» → «a.bak -> db»."""
    return _PATH_RE.sub(lambda m: file_name(m.group(0)) or m.group(0), str(text or ""))


def fmt_size(n):
    return "%.2f ГБ" % (n / 1e9) if n >= 1e9 else "%.1f МБ" % (n / 1e6) if n >= 1e6 else "%d КБ" % max(1, -(-n // 1000))


def backup_size(path):
    """Размер созданной копии из журнала msdb; None, если узнать не удалось (уведомление уйдёт без размера)."""
    try:
        with mssql_ops.connect() as conn:
            b = mssql_ops.find_backup(conn, path)
        return int(b["compressed_size"] or b["size"]) if b else None
    except Exception:
        log.warning("Не удалось узнать размер копии для уведомления", exc_info=True)
        return None


def result_text(job, status, result):
    """Поле «Результат» в уведомлении: у копии — имя файла и размер, у восстановления — путь заменён на имя файла."""
    if job["action"] == "backup" and status == "ok":
        size = backup_size(result)
        return file_name(result) + (", %s" % fmt_size(size) if size else "")
    if job["action"] == "restore":
        return strip_paths(result)
    return result


def compose(job, status, result):
    result = result_text(job, status, result)
    ok = status == "ok"
    title = TITLES.get(job["action"], job["action"])
    subject = "%s %s: %s" % (title, "завершена" if ok and job["action"] == "backup" else
                             "завершено" if ok else "не удалась" if job["action"] == "backup" else "не удалось",
                             job["target"])
    lines = ["%s — %s" % (title, "успешно" if ok else "ОШИБКА"),
             "База: %s" % job["target"],
             "Запустил: %s" % job["username"],
             "Задача №%s" % job["id"],
             "%s: %s" % ("Результат" if ok else "Причина", result)]
    return subject, "\n".join(lines)


def send_email(cfg, subject, body):
    msg = EmailMessage()
    msg["Subject"], msg["From"], msg["To"] = subject, cfg["mail_from"], cfg["mail_to"]
    msg.set_content(body)
    ctx = ssl.create_default_context()
    if cfg["smtp_security"] == "ssl":
        smtp = smtplib.SMTP_SSL(cfg["smtp_host"], cfg["smtp_port"], timeout=TIMEOUT, context=ctx)
    else:
        smtp = smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=TIMEOUT)
    with smtp:
        if cfg["smtp_security"] == "starttls":
            smtp.starttls(context=ctx)
        if cfg["smtp_user"]:
            smtp.login(cfg["smtp_user"], cfg["smtp_password"])
        smtp.send_message(msg, to_addrs=config.split_addrs(cfg["mail_to"]))


def _socks5_connect(host, port, dest, user="", password=""):
    """Соединение через SOCKS5 (имя хоста резолвит прокси)."""
    sock = socket.create_connection((host, port), TIMEOUT)
    try:
        def need(n):
            buf = b""
            while len(buf) < n:
                chunk = sock.recv(n - len(buf))
                if not chunk:
                    raise OSError("SOCKS5: соединение закрыто прокси")
                buf += chunk
            return buf
        sock.sendall(b"\x05\x02\x00\x02" if user else b"\x05\x01\x00")
        ver, method = need(2)
        if ver != 5 or method == 0xFF:
            raise OSError("SOCKS5: прокси не принял способ авторизации")
        if method == 2:
            u, p = user.encode(), password.encode()
            sock.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
            if need(2)[1] != 0:
                raise OSError("SOCKS5: неверный логин или пароль прокси")
        name = dest[0].encode()
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + dest[1].to_bytes(2, "big"))
        _, rep, _, atyp = need(4)
        if rep != 0:
            raise OSError("SOCKS5: прокси не смог открыть соединение (код %d)" % rep)
        need({1: 4, 4: 16}.get(atyp) or need(1)[0])
        need(2)
        return sock
    except Exception:
        sock.close()
        raise


def _opener(cfg):
    """Opener для Telegram с учётом настроек прокси."""
    kind = cfg.get("telegram_proxy_type", "none")
    if kind == "none":
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))   # системные переменные прокси не используем
    host, port = cfg["telegram_proxy_host"], cfg["telegram_proxy_port"]
    user, password = cfg["telegram_proxy_user"], cfg["telegram_proxy_password"]
    if kind == "http":
        auth = "%s:%s@" % (urllib.parse.quote(user, safe=""), urllib.parse.quote(password, safe="")) if user else ""
        purl = "http://%s%s:%d" % (auth, host, port)
        return urllib.request.build_opener(urllib.request.ProxyHandler({"http": purl, "https": purl}))

    class Plain(http.client.HTTPConnection):
        def connect(self):
            self.sock = _socks5_connect(host, port, (self.host, self.port), user, password)

    class Secure(http.client.HTTPSConnection):
        def connect(self):
            raw = _socks5_connect(host, port, (self.host, self.port), user, password)
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)

    class H(urllib.request.HTTPHandler):
        def http_open(self, req):
            return self.do_open(Plain, req)

    class HS(urllib.request.HTTPSHandler):
        def https_open(self, req):
            return self.do_open(Secure, req, context=self._context)

    return urllib.request.build_opener(urllib.request.ProxyHandler({}), H, HS)


def _post_json(url, payload, opener=None):
    """POST JSON, возвращает разобранный ответ (или {}). Текст ошибок не содержит URL, чтобы не светить токены."""
    req = urllib.request.Request(url, json.dumps(payload).encode("utf-8"),
                                 {"Content-Type": "application/json; charset=utf-8"}, method="POST")
    try:
        with (opener.open(req, timeout=TIMEOUT) if opener else urllib.request.urlopen(req, timeout=TIMEOUT)) as r:
            raw = r.read(65536)
    except urllib.error.HTTPError as e:
        raw = e.read(65536)
        try:
            j = json.loads(raw)
            detail = j.get("description") or j.get("error_description") or j.get("error") or ""
        except ValueError:
            detail = ""
        raise RuntimeError("HTTP %d%s" % (e.code, ": %s" % detail if detail else ""))
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        return {}


def send_webhook(cfg, subject, body, extra=None):
    payload = {"text": "%s\n%s" % (subject, body)}
    payload.update(extra or {})
    _post_json(cfg["webhook_url"], payload)


def send_telegram(cfg, subject, body):
    text = ("%s\n\n%s" % (subject, body))[:4000]          # лимит Telegram — 4096 символов
    j = _post_json("%s/bot%s/sendMessage" % (TELEGRAM_API, cfg["telegram_token"]),
                   {"chat_id": cfg["telegram_chat"], "text": text, "disable_web_page_preview": True}, _opener(cfg))
    if j and not j.get("ok", True):
        raise RuntimeError(j.get("description") or "Telegram отклонил сообщение")


def send_bitrix(cfg, subject, body):
    url = cfg["bitrix_url"].rstrip("/") + "/im.message.add.json"
    j = _post_json(url, {"DIALOG_ID": cfg["bitrix_dialog"], "MESSAGE": "%s\n%s" % (subject, body)})
    if j.get("error"):
        raise RuntimeError("Bitrix24: %s" % (j.get("error_description") or j["error"]))


def send(cfg, channel, subject, body, extra=None):
    if channel == "email":
        config.check_email(cfg)
        send_email(cfg, subject, body)
    elif channel == "telegram":
        config.check_telegram(cfg)
        send_telegram(cfg, subject, body)
    elif channel == "bitrix24":
        config.check_bitrix(cfg)
        send_bitrix(cfg, subject, body)
    else:
        config.check_webhook(cfg)
        send_webhook(cfg, subject, body, extra)


def _deliver(cfg, job, status, result):
    subject, body = compose(job, status, result)
    extra = {"event": "%s_%s" % (job["action"], "ok" if status == "ok" else "error"), "database": job["target"],
             "job": job["id"], "user": job["username"], "status": status}
    for channel, flag in CHANNELS:
        if not cfg[flag]:
            continue
        try:
            send(cfg, channel, subject, body, extra)
        except Exception as e:
            log.warning("Уведомление (%s) не отправлено: %s", channel, e)
            history.add(SYSTEM, "notify", job["target"], "error",
                        "%s: не отправлено (задача №%s): %s" % (channel, job["id"], e))


def job_finished(job, status, result):
    """Вызывается рабочим потоком после завершения задачи очереди. Отправка идёт в отдельном потоке,
    чтобы медленный SMTP не задерживал очередь."""
    try:
        cfg = config.load("notify")
        if not cfg.get(event_key(job["action"], status)) or not any(cfg[flag] for _, flag in CHANNELS):
            return None
        t = threading.Thread(target=_deliver, args=(cfg, job, status, result), daemon=True, name="notify")
        t.start()
        return t
    except Exception:
        log.exception("Сбой уведомления")
        return None
