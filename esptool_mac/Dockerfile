ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.20
FROM ${BUILD_FROM}

RUN apk add --no-cache python3

COPY app.py /app.py
EXPOSE 8900
CMD ["python3", "-u", "/app.py"]
