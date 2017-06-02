# Dockerfile for Azure/blobxfer

FROM alpine:3.6
MAINTAINER Fred Park <https://github.com/Azure/blobxfer>

RUN apk add --update --no-cache musl build-base python3 python3-dev libressl-dev libffi-dev ca-certificates \
    && pip3 install --no-cache-dir --upgrade blobxfer \
    && apk del --purge build-base python3-dev libressl-dev libffi-dev \
    && rm /var/cache/apk/*

ENTRYPOINT ["blobxfer"]
