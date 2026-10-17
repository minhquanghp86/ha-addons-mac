ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.20
FROM ${BUILD_FROM}

RUN apk add --no-cache python3

COPY app.py /app.py
WORKDIR /
EXPOSE 8900

# KHONG dung ENTRYPOINT /init: Supervisor chay container voi --init (tini la PID 1),
# nen /init cua s6 se la PID 2 -> "s6-overlay-suexec: can only run as pid 1".
CMD ["python3", "-u", "/app.py"]
