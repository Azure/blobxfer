# Dockerfile for Azure/blobxfer

FROM gliderlabs/alpine:3.4

RUN apk add --update --no-cache musl build-base python3 python3-dev openssl-dev libffi-dev ca-certificates \
    && pip3 install --no-cache-dir --upgrade pip \
    && pip3 install --no-cache-dir --upgrade blobxfer \
    && apk del --purge build-base python3-dev openssl-dev libffi-dev \
    && rm /var/cache/apk/*

ENTRYPOINT ["blobxfer"]
