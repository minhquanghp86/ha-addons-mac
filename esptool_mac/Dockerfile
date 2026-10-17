ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.20
FROM ${BUILD_FROM}

# Base image HA dat ENTRYPOINT ["/init"] (s6). Supervisor lai chay container voi --init (tini = PID 1),
# nen phai XOA entrypoint ke thua, neu khong se loi "s6-overlay-suexec: can only run as pid 1".
ENTRYPOINT []

RUN apk add --no-cache python3

COPY app.py /app.py
WORKDIR /
EXPOSE 8900
CMD ["python3", "-u", "/app.py"]
