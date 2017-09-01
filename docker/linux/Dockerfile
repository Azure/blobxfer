# Dockerfile for Azure/blobxfer (Linux)

FROM alpine:3.6
MAINTAINER Fred Park <https://github.com/Azure/blobxfer>

ARG GIT_BRANCH
ARG GIT_COMMIT

RUN apk update \
    && apk add --update --no-cache musl \
        musl build-base python3 python3-dev libressl-dev libffi-dev \
        ca-certificates git \
    && git clone -b $GIT_BRANCH --single-branch --depth 5 https://github.com/Azure/blobxfer.git /blobxfer \
    && cd /blobxfer \
    && git checkout $GIT_COMMIT \
    && pip3 install --no-cache-dir -e . \
    && python3 setup.py install \
    && cd / \
    && rm -rf blobxfer \
    && apk del --purge build-base python3-dev libressl-dev libffi-dev git \
    && rm /var/cache/apk/*

ENTRYPOINT ["blobxfer"]
