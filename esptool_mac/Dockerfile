ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:3.20
FROM ${BUILD_FROM}

RUN apk add --no-cache python3

COPY app.py /app.py
COPY run.sh /run.sh
RUN chmod a+x /run.sh

ENTRYPOINT ["/init"]
CMD ["/run.sh"]
