ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN apk add --no-cache python3

COPY app.py /app.py
EXPOSE 8900
CMD ["python3", "-u", "/app.py"]
