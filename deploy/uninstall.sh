#!/usr/bin/env bash
# Удаление MSSQL Backup.
#   sudo ./deploy/uninstall.sh           # настройки и история остаются
#   sudo ./deploy/uninstall.sh --purge   # удалить и настройки, и историю
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Запустите от root: sudo $0"; exit 1; }

systemctl disable --now mssql-backup mssql-backup-tls.path 2>/dev/null || true
rm -f /etc/systemd/system/mssql-backup.service /etc/systemd/system/mssql-backup-tls.service \
      /etc/systemd/system/mssql-backup-tls.path /etc/nginx/conf.d/mssql-backup.conf /etc/nginx/mssql-backup-locations.inc
systemctl daemon-reload
rm -rf /opt/mssql-backup
if systemctl is-active --quiet nginx && nginx -t 2>/dev/null; then systemctl reload nginx; fi

if [ "${1:-}" = "--purge" ]; then
  rm -rf /etc/mssql-backup /var/lib/mssql-backup /etc/ssl/mssql-backup
  userdel mssql-backup 2>/dev/null || true
  echo "Удалено полностью, включая настройки и историю."
else
  echo "Удалено. Настройки (/etc/mssql-backup) и данные (/var/lib/mssql-backup) сохранены; --purge удалит и их."
fi
echo "Пакеты nginx и python3 не удалялись."
