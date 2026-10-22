"""Проверка логина/пароля через LDAP / Active Directory (ldap3) и определение роли по группам."""
import os
import ssl

from ldap3 import Server, Connection, Tls, SUBTREE, BASE, NONE
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

ROLE_ORDER = (("full", "full_group_dn"), ("operator", "operator_group_dn"), ("viewer", "viewer_group_dn"))


class AuthError(Exception):
    """Текст предназначен администратору (экран настроек). Обычному пользователю
    на странице входа показывается только общее «Неверный логин или пароль»."""


def _server(cfg):
    tls = None
    if cfg["security"] in ("ldaps", "starttls"):
        tls = Tls(
            validate=ssl.CERT_REQUIRED if cfg["verify_cert"] else ssl.CERT_NONE,
            ca_certs_file=os.environ.get("LDAP_CA_FILE") or None,
        )
    return Server(cfg["host"], port=int(cfg["port"]), use_ssl=cfg["security"] == "ldaps",
                  tls=tls, connect_timeout=int(cfg["timeout"]), get_info=NONE)


def _connect(cfg, user=None, password=None):
    """Открывает соединение и делает bind. Без user — анонимный bind."""
    conn = Connection(_server(cfg), user=user or None, password=password or None,
                      receive_timeout=int(cfg["timeout"]), raise_exceptions=False)
    try:
        conn.open()
        if cfg["security"] == "starttls" and not conn.start_tls():
            raise AuthError("StartTLS не удался: " + str(conn.result.get("description")))
        if not conn.bind():
            raise AuthError("Сервер отклонил привязку: " + str(conn.result.get("description")))
    except LDAPException as e:
        raise AuthError("Ошибка соединения с LDAP: %s" % e)
    return conn


def _norm_dn(dn):
    return ",".join(part.strip() for part in dn.strip().lower().split(","))


def _lower_attrs(entry):
    return {k.lower(): v for k, v in entry.entry_attributes_as_dict.items()}


def test_connection(cfg):
    """Проверяет доступность сервера, bind служебной учётки и Base DN."""
    conn = _connect(cfg, cfg["bind_dn"], cfg["bind_password"])
    try:
        ok = conn.search(cfg["base_dn"], "(objectClass=*)", search_scope=BASE, attributes=[], size_limit=1)
        if not ok:
            raise AuthError("Base DN недоступен: " + str(conn.result.get("description")))
    finally:
        conn.unbind()
    return "Соединение установлено, bind выполнен (%s), Base DN доступен" % (cfg["bind_dn"] or "анонимно")


def role_for(cfg, groups):
    """Самая высокая роль среди групп пользователя или None."""
    member = {_norm_dn(g) for g in groups}
    for role, key in ROLE_ORDER:
        if cfg[key] and _norm_dn(cfg[key]) in member:
            return role
    return None


def authenticate(cfg, username, password):
    # Пустой пароль нельзя отдавать серверу: bind с пустым паролем у многих
    # LDAP считается «анонимным» и проходит успешно.
    if not username or not password:
        raise AuthError("Пустой логин или пароль")

    svc = _connect(cfg, cfg["bind_dn"], cfg["bind_password"])
    try:
        flt = cfg["user_filter"].replace("{username}", escape_filter_chars(username))
        svc.search(cfg["base_dn"], flt, search_scope=SUBTREE,
                   attributes=["memberOf", "displayName", "cn"], size_limit=2)
        entries = list(svc.entries)
    finally:
        svc.unbind()

    if not entries:
        raise AuthError("Пользователь не найден по заданному фильтру")
    if len(entries) > 1:
        raise AuthError("Фильтр нашёл несколько пользователей — уточните его")

    entry = entries[0]
    dn = entry.entry_dn
    attrs = _lower_attrs(entry)

    try:
        _connect(cfg, dn, password).unbind()
    except AuthError:
        raise AuthError("Неверный пароль")

    role = role_for(cfg, [str(g) for g in attrs.get("memberof", [])])
    if not role:
        raise AuthError("Пользователь не входит ни в одну из групп доступа")

    display = ""
    for key in ("displayname", "cn"):
        vals = attrs.get(key) or []
        if vals:
            display = str(vals[0])
            break
    return {"name": username, "display": display or username, "source": "ldap", "role": role, "dn": dn}
