"""HTTPS-сертификат веб-интерфейса: запрос (CSR) для доменного центра сертификации и установка выданного сертификата.

Как это устроено:
  * служба (без прав root) создаёт закрытый ключ и CSR командой `openssl` и хранит их в <DATA_DIR>/tls/ (pending.*);
  * администратор получает сертификат в центре сертификации (например, AD CS) и загружает его в веб-интерфейс;
  * служба проверяет сертификат (соответствие ключу, срок, цепочка), кладёт ключ и цепочку в <DATA_DIR>/tls/ и записывает
    request.json — это запускает от root отдельную systemd-службу mssql-backup-tls (deploy/apply-tls.py), которая
    копирует файлы в /etc/ssl/mssql-backup, перенастраивает nginx, проверяет `nginx -t` и перезагружает его;
  * результат применения служба читает из status.json.
Ничего из пользовательского ввода не попадает в конфигурацию nginx: имена и пути там фиксированные.
"""
import base64
import datetime
import ipaddress
import json
import os
import re
import subprocess
import tempfile
import uuid

import config

TLS_DIR = os.path.join(config.DATA_DIR, "tls")
INSTALLED_CERT = os.environ.get("TLS_INSTALLED_CERT", "/etc/ssl/mssql-backup/server.crt")
OPENSSL = os.environ.get("OPENSSL_BIN", "openssl")
KEY_BITS = (2048, 3072, 4096)
MAX_CERT_BYTES = 200_000

_NAME_OK = re.compile(r"^[\w .,'()&@+\-]{1,64}$", re.UNICODE)
_DNS_OK = re.compile(r"^(\*\.)?([A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$")


class TlsError(ValueError):
    """Ошибка, текст которой можно показать пользователю."""


def _path(name):
    return os.path.join(TLS_DIR, name)


def _ensure_dir():
    os.makedirs(TLS_DIR, mode=0o700, exist_ok=True)


def _write(name, data, mode=0o600):
    _ensure_dir()
    path = _path(name)
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data if isinstance(data, bytes) else data.encode("utf-8"))
    os.replace(tmp, path)


def _read(name):
    try:
        with open(_path(name), "rb") as f:
            return f.read()
    except FileNotFoundError:
        return None


def _remove(*names):
    for n in names:
        try:
            os.unlink(_path(n))
        except FileNotFoundError:
            pass


def _run(args, data=None, check=True):
    try:
        p = subprocess.run([OPENSSL] + args, input=data, capture_output=True, timeout=30)
    except FileNotFoundError:
        raise TlsError("Команда openssl не найдена на сервере")
    except subprocess.TimeoutExpired:
        raise TlsError("openssl не ответил вовремя")
    if check and p.returncode != 0:
        raise TlsError("Ошибка openssl: " + (p.stderr.decode("utf-8", "replace").strip().splitlines() or ["?"])[-1])
    return p


# ---------- запрос сертификата ----------
def _clean_name(value, label, required=False):
    value = str(value or "").strip()
    if not value:
        if required:
            raise TlsError("Укажите «%s»" % label)
        return ""
    if not _NAME_OK.match(value):
        raise TlsError("«%s»: допустимы буквы, цифры, пробел и . , ' ( ) & @ + - (до 64 символов)" % label)
    return value


def _clean_san(item):
    item = str(item or "").strip()
    if not item:
        return None
    try:
        return ("IP", str(ipaddress.ip_address(item)))
    except ValueError:
        pass
    if len(item) > 253 or not _DNS_OK.match(item):
        raise TlsError("Некорректное имя или IP в списке адресов: «%s»" % item[:60])
    return ("DNS", item.lower())


def split_list(value):
    if isinstance(value, list):
        value = ",".join(str(v) for v in value)
    return [p for p in re.split(r"[,;\s]+", str(value or "")) if p]


def create_csr(cn, sans=None, org="", unit="", country="", state="", city="", key_bits=2048):
    """Создаёт ключ и CSR (заменяет прежний неустановленный запрос). Возвращает описание запроса."""
    cn = str(cn or "").strip().lower()
    if not _DNS_OK.match(cn) or len(cn) > 64:
        try:
            ipaddress.ip_address(cn)
        except ValueError:
            raise TlsError("«Имя сервера» (CN) — DNS-имя веб-интерфейса, например backup.corp.local (до 64 символов)")
    try:
        key_bits = int(key_bits)
    except (TypeError, ValueError):
        raise TlsError("Некорректный размер ключа")
    if key_bits not in KEY_BITS:
        raise TlsError("Размер ключа: 2048, 3072 или 4096")
    entries = [("IP", cn) if _is_ip(cn) else ("DNS", cn)]               # CN обязательно дублируется в SAN
    for s in split_list(sans):
        e = _clean_san(s)
        if e and e not in entries:
            entries.append(e)
    if len(entries) > 20:
        raise TlsError("Слишком много альтернативных имён (максимум 20)")
    org, unit = _clean_name(org, "Организация"), _clean_name(unit, "Подразделение")
    state, city = _clean_name(state, "Область"), _clean_name(city, "Город")
    country = str(country or "").strip().upper()
    if country and not re.match(r"^[A-Z]{2}$", country):
        raise TlsError("Страна — двухбуквенный код, например RU")

    dn = [("C", country), ("ST", state), ("L", city), ("O", org), ("OU", unit), ("CN", cn)]
    dn = [(k, v) for k, v in dn if v]
    alt = "\n".join("%s.%d = %s" % (kind, i, val) for i, (kind, val) in enumerate(entries, 1))
    cfg = ("[req]\ndistinguished_name = dn\nreq_extensions = ext\nprompt = no\nutf8 = yes\nstring_mask = utf8only\n"
           "default_md = sha256\n[dn]\n" + "\n".join("%s = %s" % kv for kv in dn)
           + "\n[ext]\nsubjectAltName = @alt\nkeyUsage = critical, digitalSignature, keyEncipherment\n"
             "extendedKeyUsage = serverAuth\nbasicConstraints = CA:FALSE\n[alt]\n" + alt + "\n")
    _ensure_dir()
    with tempfile.TemporaryDirectory(dir=TLS_DIR) as tmp:
        conf, key, csr = (os.path.join(tmp, n) for n in ("req.cnf", "k.pem", "r.csr"))
        with open(conf, "w", encoding="utf-8") as f:
            f.write(cfg)
        old = os.umask(0o077)
        try:
            _run(["req", "-new", "-newkey", "rsa:%d" % key_bits, "-nodes", "-keyout", key, "-out", csr, "-config", conf])
        finally:
            os.umask(old)
        with open(key, "rb") as f:
            key_pem = f.read()
        with open(csr, "rb") as f:
            csr_pem = f.read()
    meta = {"cn": cn, "sans": ["%s:%s" % e for e in entries], "subject": ", ".join("%s=%s" % kv for kv in dn),
            "key_bits": key_bits, "created": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    _write("pending.key", key_pem)
    _write("pending.csr", csr_pem, 0o644)
    _write("pending.json", json.dumps(meta, ensure_ascii=False))
    return pending()


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def pending():
    """Описание неустановленного запроса и текст CSR; None, если запроса нет."""
    raw, csr = _read("pending.json"), _read("pending.csr")
    if raw is None or csr is None or _read("pending.key") is None:
        return None
    try:
        meta = json.loads(raw)
    except ValueError:
        return None
    meta["csr"] = csr.decode("ascii", "replace")
    return meta


def cancel_pending():
    _remove("pending.key", "pending.csr", "pending.json")


def csr_pem():
    return _read("pending.csr")


# ---------- разбор выданного сертификата ----------
_PEM_BLOCK = re.compile(rb"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", re.S)


def _pems_from_pkcs7(data, inform):
    p = _run(["pkcs7", "-print_certs", "-inform", inform], data, check=False)
    if p.returncode != 0:
        return []
    return [m.group(0) for m in _PEM_BLOCK.finditer(p.stdout) if m.group(1) == b"CERTIFICATE"]


def extract_certs(data):
    """Достаёт сертификаты из PEM (с цепочкой), DER (.cer/.crt) или PKCS#7 (.p7b). Возвращает список PEM (bytes)."""
    if not data or len(data) > MAX_CERT_BYTES:
        raise TlsError("Файл сертификата пустой или слишком большой")
    certs = []
    if b"-----BEGIN" in data:
        for m in _PEM_BLOCK.finditer(data):
            kind = m.group(1)
            if kind in (b"CERTIFICATE", b"TRUSTED CERTIFICATE", b"X509 CERTIFICATE"):
                certs.append(m.group(0))
            elif kind == b"PKCS7":
                certs += _pems_from_pkcs7(m.group(0), "PEM")
            elif kind in (b"PRIVATE KEY", b"RSA PRIVATE KEY", b"ENCRYPTED PRIVATE KEY", b"EC PRIVATE KEY"):
                raise TlsError("В файле закрытый ключ. Загрузите только сертификат (закрытый ключ остаётся на сервере)")
    else:
        p = _run(["x509", "-inform", "DER", "-outform", "PEM"], data, check=False)
        if p.returncode == 0 and p.stdout.strip():
            certs.append(p.stdout)
        else:
            certs += _pems_from_pkcs7(data, "DER")
    if not certs:
        raise TlsError("Сертификат не распознан. Нужен файл в формате PEM, DER (.cer/.crt) или PKCS#7 (.p7b)")
    return certs


def _text(args, pem):
    return _run(args, pem).stdout.decode("utf-8", "replace").strip()


def _pubkey_of_cert(pem):
    return _run(["x509", "-noout", "-pubkey"], pem).stdout.strip()


def describe(pem):
    """Сведения о сертификате (первый в PEM)."""
    out = _text(["x509", "-noout", "-subject", "-issuer", "-serial", "-startdate", "-enddate", "-fingerprint", "-sha256",
                 "-nameopt", "RFC2253"], pem)
    info = {}
    for line in out.splitlines():
        k, _, v = line.partition("=")
        info[k.strip()] = v.strip()
    san = _run(["x509", "-noout", "-ext", "subjectAltName"], pem, check=False).stdout.decode("utf-8", "replace")
    sans = re.findall(r"(?:DNS|IP Address):\s*([^,\s]+)", san)
    cn = re.search(r"CN=([^,]+)", info.get("subject", ""))
    not_after = _parse_openssl_date(info.get("notAfter", ""))
    return {"subject": info.get("subject", ""), "issuer": info.get("issuer", ""), "cn": cn.group(1) if cn else "",
            "serial": info.get("serial", ""), "not_before": _iso(_parse_openssl_date(info.get("notBefore", ""))),
            "not_after": _iso(not_after), "sans": sans, "sha256": info.get("sha256 Fingerprint", info.get("SHA256 Fingerprint", "")),
            "expired": bool(not_after and not_after < datetime.datetime.now(datetime.timezone.utc)),
            "days_left": (not_after - datetime.datetime.now(datetime.timezone.utc)).days if not_after else None}


def _parse_openssl_date(text):
    try:
        return datetime.datetime.strptime(text.strip(), "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ") if dt else ""


def _names(pem):
    out = _text(["x509", "-noout", "-subject", "-issuer", "-nameopt", "RFC2253"], pem)
    d = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return d.get("subject", "").strip(), d.get("issuer", "").strip()


def build_chain(certs):
    """Оставляет лист (по совпадению с ключом запроса) и промежуточные сертификаты, упорядочивает «лист → центр».
    Корневой (самоподписанный) сертификат в цепочку не включается: клиенты доверяют ему сами."""
    key = _read("pending.key")
    if key is None:
        raise TlsError("Нет неустановленного запроса: сначала создайте запрос (CSR)")
    my_pub = _run(["pkey", "-pubout"], key).stdout.strip()
    leaf = next((c for c in certs if _pubkey_of_cert(c) == my_pub), None)
    if leaf is None:
        raise TlsError("Сертификат не соответствует созданному на сервере запросу (другой открытый ключ). Загрузите сертификат, "
                       "выданный именно по этому CSR, либо создайте новый запрос")
    names = {id(c): _names(c) for c in certs}
    chain, cur, seen = [leaf], leaf, {id(leaf)}
    while True:
        subj, issuer = names[id(cur)]
        if subj == issuer:
            break
        nxt = next((c for c in certs if id(c) not in seen and names[id(c)][0] == issuer), None)
        if nxt is None:
            break
        seen.add(id(nxt))
        if names[id(nxt)][0] == names[id(nxt)][1]:            # корневой не добавляем
            break
        chain.append(nxt)
        cur = nxt
    return chain


def validate_and_stage(data, https_port=443, redirect_http=True, who=""):
    """Проверяет присланный сертификат и передаёт его на применение (запись request.json запускает службу от root)."""
    try:
        https_port = int(https_port)
    except (TypeError, ValueError):
        raise TlsError("Порт HTTPS должен быть числом")
    if not 1 <= https_port <= 65535:
        raise TlsError("Порт HTTPS — от 1 до 65535")
    certs = extract_certs(data)
    chain = build_chain(certs)
    info = describe(chain[0])
    if info["expired"]:
        raise TlsError("Срок действия сертификата истёк (%s)" % info["not_after"])
    started = _parse_openssl_date(_run(["x509", "-noout", "-startdate"], chain[0]).stdout.decode().split("=", 1)[-1])
    if started and started > datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5):
        raise TlsError("Сертификат ещё не действует (начало: %s). Проверьте время на сервере" % info["not_before"])
    pend = pending()
    warnings = []
    if pend and pend["cn"] not in [s.lower() for s in info["sans"]] and pend["cn"] != info["cn"].lower():
        warnings.append("Имя «%s» из запроса не найдено в сертификате — браузеры могут отклонить его" % pend["cn"])
    fullchain = b"\n".join(c.strip() + b"\n" for c in chain)
    rid = uuid.uuid4().hex
    _remove("status.json")
    _write("server.crt", fullchain, 0o644)
    _write("server.key", _read("pending.key"))
    _write("request.json", json.dumps({"id": rid, "https_port": https_port, "redirect_http": bool(redirect_http),
                                        "by": str(who)[:100],
                                        "time": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}))
    return {"id": rid, "certificate": info, "chain_length": len(chain), "warnings": warnings}


# ---------- состояние ----------
def installed():
    """Сведения об установленном сейчас сертификате (None, если HTTPS не настроен)."""
    try:
        with open(INSTALLED_CERT, "rb") as f:
            data = f.read()
    except OSError:
        return None
    try:
        return describe(data)
    except TlsError:
        return None


def apply_status():
    raw = _read("status.json")
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def waiting_request():
    """Запрос на применение, которого служба root ещё не обработала (request.json остался на месте)."""
    raw = _read("request.json")
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def der_from_b64(text):
    try:
        return base64.b64decode(text, validate=False)
    except Exception:
        raise TlsError("Файл не удалось прочитать")
