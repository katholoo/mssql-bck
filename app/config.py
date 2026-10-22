"""Настройки приложения (LDAP и хранилище копий) в JSON-файле с правами 0600."""
import json
import logging
import os
import re
import threading

log = logging.getLogger("backup")

DATA_DIR = os.environ.get("DATA_DIR", "/var/lib/mssql-backup")
SETTINGS_FILE = os.path.join(DATA_DIR, "settings.json")
_lock = threading.Lock()

DEFAULTS = {
    "ldap": {
        "enabled": False,
        "host": "",
        "port": 389,
        "security": "none",            # none | ldaps | starttls
        "verify_cert": True,
        "bind_dn": "",
        "bind_password": "",
        "base_dn": "",
        "user_filter": "(sAMAccountName={username})",
        # Группы доступа: пользователь получает самую высокую из найденных ролей
        "full_group_dn": "",           # полный доступ
        "operator_group_dn": "",       # создание и восстановление копий
        "viewer_group_dn": "",         # только просмотр
        "timeout": 10,
    },
    "storage": {
        "type": "local",               # local | smb | s3
        "local_path": os.environ.get("MSSQL_BACKUP_DIR", "/var/opt/mssql/backup"),
        "smb_path": "",
        "s3_endpoint": "",
        "s3_port": 443,
        "s3_bucket": "",
        "s3_prefix": "",
        "s3_access_key": "",
        "s3_secret_key": "",
        "s3_virtual_host": False,
    },
    "notify": {
        # e-mail
        "email_enabled": False,
        "smtp_host": "",
        "smtp_port": 587,
        "smtp_security": "starttls",   # none | starttls | ssl
        "smtp_user": "",
        "smtp_password": "",
        "mail_from": "",
        "mail_to": "",                 # несколько адресов через запятую или пробел
        # webhook (Slack, Mattermost, Teams, Telegram-прокси и т.п.): POST JSON {"text": ...}
        "webhook_enabled": False,
        "webhook_url": "",
        # Telegram-бот: сообщение уходит в чат/группу/канал, куда добавлен бот
        "telegram_enabled": False,
        "telegram_token": "",          # токен от @BotFather
        "telegram_chat": "",           # числовой id чата (для групп отрицательный) или @канал
        "telegram_proxy_type": "none", # none | http | socks5 (прокси только для Telegram)
        "telegram_proxy_host": "",
        "telegram_proxy_port": 3128,
        "telegram_proxy_user": "",
        "telegram_proxy_password": "",
        # Bitrix24 (облако): входящий вебхук с правом «Чат и уведомления» (im)
        "bitrix_enabled": False,
        "bitrix_url": "",              # https://<портал>.bitrix24.ru/rest/<id>/<код>/
        "bitrix_dialog": "",           # id пользователя или chat<N> (групповой чат)
        # о каких событиях сообщать
        "ev_backup_ok": True,
        "ev_backup_error": True,
        "ev_restore_ok": True,
        "ev_restore_error": True,
    },
}
SECRET = {"ldap": ("bind_password",), "storage": ("s3_secret_key",),
          "notify": ("smtp_password", "webhook_url", "telegram_token", "bitrix_url",
                      "telegram_proxy_password")}     # секреты не отдаются в браузер


def _read_all():
    try:
        with open(SETTINGS_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except Exception:
        log.exception("Не удалось прочитать %s", SETTINGS_FILE)
        return {}


def load(section):
    cfg = dict(DEFAULTS[section])
    cfg.update({k: v for k, v in _read_all().get(section, {}).items() if k in cfg})
    return cfg


def save(section, cfg):
    with _lock:
        os.makedirs(DATA_DIR, exist_ok=True)
        data = _read_all()
        data[section] = cfg
        tmp = SETTINGS_FILE + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, SETTINGS_FILE)


def public(section, cfg):
    """Копия настроек без секрета (вместо него флаг *_set)."""
    out = dict(cfg)
    for secret in SECRET[section]:
        out[secret + "_set"] = bool(out.pop(secret, ""))
    return out


def changed_keys(old, new):
    return [k for k in new if new[k] != old.get(k)]


def build(section, data, old, mode="save"):
    """Склеивает присланные поля со старыми настройками, нормализует и проверяет.
    mode: "save" — сохранение, "test" — проверка соединения (требования мягче)."""
    secrets = SECRET[section]
    new = dict(old)
    for key in DEFAULTS[section]:
        if key not in secrets and key in data:
            new[key] = data[key]
    for secret in secrets:
        if data.get("clear_" + secret):
            new[secret] = ""
        elif data.get(secret):
            new[secret] = str(data[secret])
    {"ldap": _norm_ldap, "storage": _norm_storage, "notify": _norm_notify}[section](new, mode)
    return new


def _norm_ldap(new, mode):
    for key in ("host", "bind_dn", "base_dn", "user_filter",
                "full_group_dn", "operator_group_dn", "viewer_group_dn"):
        new[key] = str(new[key] or "").strip()
    new["enabled"] = bool(new["enabled"])
    new["verify_cert"] = bool(new["verify_cert"])
    try:
        new["port"] = int(new["port"])
        new["timeout"] = int(new["timeout"])
    except (TypeError, ValueError):
        raise ValueError("Порт и таймаут должны быть числами")
    if not 1 <= new["port"] <= 65535:
        raise ValueError("Порт должен быть от 1 до 65535")
    if not 1 <= new["timeout"] <= 120:
        raise ValueError("Таймаут должен быть от 1 до 120 секунд")
    if new["security"] not in ("none", "ldaps", "starttls"):
        raise ValueError("Неизвестный режим шифрования")

    if mode == "test" or new["enabled"]:
        if not new["host"]:
            raise ValueError("Укажите адрес сервера")
        if not new["base_dn"]:
            raise ValueError("Укажите Base DN")
        if "{username}" not in new["user_filter"]:
            raise ValueError("Фильтр пользователя должен содержать {username}")
        if new["bind_dn"] and not new["bind_password"]:
            raise ValueError("Для Bind DN нужен пароль")
    if mode == "save" and new["enabled"]:
        if not (new["full_group_dn"] or new["operator_group_dn"] or new["viewer_group_dn"]):
            raise ValueError(
                "Укажите хотя бы одну группу доступа, иначе никто кроме локального "
                "администратора не сможет войти")


def _norm_storage(new, mode):
    for key in ("local_path", "smb_path", "s3_endpoint", "s3_bucket", "s3_prefix", "s3_access_key"):
        new[key] = str(new[key] or "").strip()
    new["s3_secret_key"] = str(new["s3_secret_key"] or "")
    new["s3_virtual_host"] = bool(new["s3_virtual_host"])
    if new["type"] not in ("local", "smb", "s3"):
        raise ValueError("Неизвестный тип хранилища")

    endpoint = re.sub(r"^(?:https?|s3)://", "", new["s3_endpoint"], flags=re.I).strip("/")
    m = re.match(r"^(.+):(\d{1,5})$", endpoint)
    if m:
        endpoint, new["s3_port"] = m.group(1), m.group(2)
    new["s3_endpoint"] = endpoint
    new["s3_prefix"] = new["s3_prefix"].strip("/")
    try:
        new["s3_port"] = int(new["s3_port"])
    except (TypeError, ValueError):
        raise ValueError("Порт S3 должен быть числом")

    if new["smb_path"].startswith("//"):
        new["smb_path"] = new["smb_path"].replace("/", "\\")
    new["smb_path"] = new["smb_path"].rstrip("\\")

    kind = new["type"]
    if kind == "local" and not new["local_path"]:
        raise ValueError("Укажите папку на сервере SQL Server")
    if kind == "smb" and not re.match(r"^\\\\[^\\/]+\\[^\\/]+", new["smb_path"]):
        raise ValueError("SMB-путь должен иметь вид \\\\сервер\\ресурс или \\\\сервер\\ресурс\\папка")
    if kind == "s3":
        if not new["s3_endpoint"]:
            raise ValueError("Укажите адрес S3 (endpoint)")
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9.\-_]*$", new["s3_bucket"]):
            raise ValueError("Укажите корректное имя бакета")
        if not 1 <= new["s3_port"] <= 65535:
            raise ValueError("Порт S3 должен быть от 1 до 65535")
        if not new["s3_access_key"] or not new["s3_secret_key"]:
            raise ValueError("Укажите Access Key и Secret Key")
        if ":" in new["s3_access_key"]:
            raise ValueError("Access Key не может содержать двоеточие")


EMAIL_RE = re.compile(r"^[^@\s<>,;]+@[^@\s<>,;]+\.[^@\s<>,;]+$")


def split_addrs(text):
    return [a for a in re.split(r"[,;\s]+", str(text or "")) if a]


def _norm_notify(new, mode):
    for key in ("smtp_host", "smtp_user", "mail_from", "webhook_url", "telegram_token", "telegram_chat",
                "bitrix_url", "bitrix_dialog", "telegram_proxy_host", "telegram_proxy_user"):
        new[key] = str(new[key] or "").strip()
    new["smtp_password"] = str(new["smtp_password"] or "")
    new["mail_to"] = ", ".join(split_addrs(new["mail_to"]))
    for key in ("email_enabled", "webhook_enabled", "telegram_enabled", "bitrix_enabled", "ev_backup_ok", "ev_backup_error", "ev_restore_ok", "ev_restore_error"):
        new[key] = bool(new[key])
    if new["smtp_security"] not in ("none", "starttls", "ssl"):
        raise ValueError("Неизвестный режим шифрования SMTP")
    try:
        new["smtp_port"] = int(new["smtp_port"])
    except (TypeError, ValueError):
        raise ValueError("Порт SMTP должен быть числом")
    if not 1 <= new["smtp_port"] <= 65535:
        raise ValueError("Порт SMTP должен быть от 1 до 65535")
    new["telegram_proxy_password"] = str(new["telegram_proxy_password"] or "")
    if new["telegram_proxy_type"] not in ("none", "http", "socks5"):
        raise ValueError("Неизвестный тип прокси")
    try:
        new["telegram_proxy_port"] = int(new["telegram_proxy_port"])
    except (TypeError, ValueError):
        raise ValueError("Порт прокси должен быть числом")
    if new["telegram_proxy_type"] != "none":
        if not re.match(r"^[A-Za-z0-9][A-Za-z0-9.\-_]*$|^\[[0-9A-Fa-f:.]+\]$", new["telegram_proxy_host"]):
            raise ValueError("Укажите адрес прокси-сервера (имя или IP, без http://)")
        if not 1 <= new["telegram_proxy_port"] <= 65535:
            raise ValueError("Порт прокси должен быть от 1 до 65535")
        if new["telegram_proxy_password"] and not new["telegram_proxy_user"]:
            raise ValueError("Для пароля прокси нужен пользователь")
    if new["smtp_user"] and not new["smtp_password"]:
        raise ValueError("Для пользователя SMTP нужен пароль")
    if mode == "save":
        if new["email_enabled"]:
            check_email(new)
        if new["webhook_enabled"]:
            check_webhook(new)
        if new["telegram_enabled"]:
            check_telegram(new)
        if new["bitrix_enabled"]:
            check_bitrix(new)


def check_email(cfg):
    if not cfg["smtp_host"]:
        raise ValueError("Укажите SMTP-сервер")
    if not EMAIL_RE.match(cfg["mail_from"]):
        raise ValueError("Укажите корректный адрес отправителя")
    to = split_addrs(cfg["mail_to"])
    if not to or not all(EMAIL_RE.match(a) for a in to):
        raise ValueError("Укажите корректные адреса получателей")


def check_webhook(cfg):
    if not re.match(r"^https?://[^\s/]+", cfg["webhook_url"], re.I):
        raise ValueError("Адрес webhook должен начинаться с http:// или https://")


def check_telegram(cfg):
    if not re.match(r"^\d{5,}:[A-Za-z0-9_-]{20,}$", cfg["telegram_token"]):
        raise ValueError("Укажите токен бота от @BotFather (вида 123456:ABC…)")
    if not re.match(r"^(-?\d+|@[A-Za-z][A-Za-z0-9_]{3,})$", cfg["telegram_chat"]):
        raise ValueError("Чат: числовой id (для группы — отрицательный) или @имя_канала")


def check_bitrix(cfg):
    if not re.match(r"^https?://[^\s/]+/rest/\d+/[A-Za-z0-9]+/?$", cfg["bitrix_url"]):
        raise ValueError("Адрес вебхука Bitrix24 должен иметь вид https://портал.bitrix24.ru/rest/1/код/")
    if not re.match(r"^(\d+|chat\d+)$", cfg["bitrix_dialog"]):
        raise ValueError("Получатель Bitrix24: id пользователя или chatN (номер группового чата)")
