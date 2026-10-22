# Общая часть server-блоков nginx (HTTP и HTTPS). Ставится в /etc/nginx/mssql-backup-locations.inc.
root /opt/mssql-backup/web;
index index.html;

add_header X-Content-Type-Options nosniff always;
add_header X-Frame-Options DENY always;
add_header Referrer-Policy same-origin always;

location / {
    try_files $uri /index.html;
    # Страница всегда перепроверяется: после обновления не остаётся старая версия в кэше браузера.
    # add_header в location отключает наследование заголовков сервера, поэтому они повторены.
    add_header Cache-Control "no-cache" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy same-origin always;
}

location /api/ {
    proxy_pass http://127.0.0.1:8000/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    # Приложение по этому заголовку ставит cookie сессии с флагом Secure (только при HTTPS)
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 120s;
}
