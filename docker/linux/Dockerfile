# Dockerfile for Azure/blobxfer (Linux)

FROM python:3.9.7-alpine3.14
MAINTAINER Fred Park <https://github.com/Azure/blobxfer>

ARG GIT_BRANCH
ARG GIT_COMMIT

RUN apk update \
    && apk add --update --no-cache \
        musl build-base openssl-dev libffi-dev rust cargo ca-certificates git \
    && python3 -m ensurepip --upgrade \
    && pip3 install --no-cache-dir --upgrade pip setuptools setuptools-rust wheel \
    && git clone -b $GIT_BRANCH --single-branch --depth 5 https://github.com/Azure/blobxfer.git /blobxfer \
    && cd /blobxfer \
    && git checkout $GIT_COMMIT \
    && pip3 install --no-cache-dir -e . \
    && python3 setup.py install \
    && cp THIRD_PARTY_NOTICES.txt /BLOBXFER_THIRD_PARTY_NOTICES.txt \
    && cp LICENSE /BLOBXFER_LICENSE.txt \
    && pip3 uninstall -y setuptools-rust wheel \
    && apk del --purge build-base patch openssl-dev libffi-dev rust cargo git \
    && rm /var/cache/apk/* \
    && rm -rf /root/.cache /root/.cargo \
    && rm -rf /blobxfer

ENTRYPOINT ["blobxfer"]
