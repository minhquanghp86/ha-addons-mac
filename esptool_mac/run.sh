#!/usr/bin/with-contenv bashio
# s6-overlay: script chạy sau khi services đã khởi động
exec python3 -u /app.py
