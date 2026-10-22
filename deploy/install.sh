#!/usr/bin/env bash
# Установка MSSQL Backup на Debian/Ubuntu без Docker.
#   sudo ./deploy/install.sh              # порт веб-интерфейса 8080
#   sudo PORT=80 ./deploy/install.sh      # другой порт
# Повторный запуск обновляет приложение; настройки и данные не затрагиваются.
set -euo pipefail

PORT="${PORT:-8080}"
APP_DIR=/opt/mssql-backup
ETC_DIR=/etc/mssql-backup
ENV_FILE="$ETC_DIR/mssql-backup.env"
DATA_DIR=/var/lib/mssql-backup
SVC_USER=mssql-backup
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "Запустите от root: sudo $0"; exit 1; }
command -v apt-get >/dev/null || { echo "Скрипт рассчитан на Debian/Ubuntu (нужен apt-get)"; exit 1; }
command -v systemctl >/dev/null || { echo "Нужен systemd"; exit 1; }
[[ "$PORT" =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || { echo "Некорректный PORT: $PORT"; exit 1; }

echo "==> Пакеты (nginx, python3)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq nginx python3 python3-venv python3-pip ca-certificates openssl

echo "==> Пользователь и каталоги"
id -u "$SVC_USER" >/dev/null 2>&1 || \
  useradd --system --home-dir "$DATA_DIR" --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
install -d -m 755 "$APP_DIR"
install -d -m 750 -o root -g "$SVC_USER" "$ETC_DIR"

echo "==> Файлы приложения"
rm -rf "$APP_DIR/app" "$APP_DIR/web"
cp -r "$SRC/app" "$APP_DIR/app"
cp -r "$SRC/web" "$APP_DIR/web"
find "$APP_DIR" -name __pycache__ -prune -exec rm -rf {} +
chown -R root:root "$APP_DIR/app" "$APP_DIR/web"
chmod -R u=rwX,go=rX "$APP_DIR/app" "$APP_DIR/web"

echo "==> Python-окружение"
python3 -m venv "$APP_DIR/venv"
PIP="$APP_DIR/venv/bin/pip"
"$PIP" install --quiet --upgrade pip
"$PIP" install --quiet -r "$APP_DIR/app/requirements.txt"

NEW_ENV=0
if [ ! -f "$ENV_FILE" ]; then
  echo "==> Файл настроек $ENV_FILE"
  ADMIN_PW="$(openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | cut -c1-20)"
  sed "s|__ADMIN_PASSWORD__|$ADMIN_PW|" "$SRC/deploy/mssql-backup.env.example" > "$ENV_FILE"
  chown root:"$SVC_USER" "$ENV_FILE"
  chmod 640 "$ENV_FILE"
  NEW_ENV=1
fi

echo "==> Служба systemd и nginx"
install -m 644 "$SRC/deploy/mssql-backup.service" /etc/systemd/system/mssql-backup.service
# Выпуск и установка HTTPS-сертификата из веб-интерфейса («Настройки → Сертификат»): служба root применяет его к nginx
install -m 644 "$SRC/deploy/mssql-backup-tls.service" /etc/systemd/system/mssql-backup-tls.service
install -m 644 "$SRC/deploy/mssql-backup-tls.path" /etc/systemd/system/mssql-backup-tls.path
install -m 755 -o root -g root "$SRC/deploy/apply-tls.py" "$APP_DIR/tls-apply.py"
install -m 644 "$SRC/deploy/nginx-locations.inc" /etc/nginx/mssql-backup-locations.inc
install -d -m 700 -o "$SVC_USER" -g "$SVC_USER" "$DATA_DIR" "$DATA_DIR/tls"
echo "$PORT" > "$ETC_DIR/web.port"
# Конфигурация формируется заново: HTTP-only либо, если сертификат уже установлен, с HTTPS (он сохраняется при обновлении)
/usr/bin/python3 "$APP_DIR/tls-apply.py" --render
nginx -t

systemctl daemon-reload
systemctl enable --now nginx >/dev/null 2>&1 || true
systemctl enable mssql-backup >/dev/null 2>&1
systemctl enable --now mssql-backup-tls.path >/dev/null 2>&1
systemctl restart mssql-backup
systemctl reload nginx

echo
echo "Готово. Веб-интерфейс: http://<адрес-этого-сервера>:$PORT/"
if [ "$NEW_ENV" = 1 ]; then
  echo
  echo "Локальный администратор: admin / $ADMIN_PW   (пароль сохранён в $ENV_FILE)"
  echo
  echo "Теперь впишите подключение к SQL Server и перезапустите службу:"
  echo "  sudo nano $ENV_FILE        # MSSQL_HOST, MSSQL_USER, MSSQL_PASSWORD"
  echo "  sudo systemctl restart mssql-backup"
fi
echo
echo "Вход по паролю идёт по HTTP. Для HTTPS откройте «Настройки → Сертификат»: создайте запрос (CSR), получите сертификат"
echo "в центре сертификации домена и загрузите его — nginx настроится автоматически (см. README)."
echo "Логи: journalctl -u mssql-backup -f"
