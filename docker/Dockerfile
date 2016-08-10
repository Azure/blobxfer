FROM gliderlabs/alpine:3.4
RUN apk add --update musl build-base python3 python3-dev openssl-dev libffi-dev bash \
    && pip3 install --upgrade pip \
    && pip3 install --upgrade blobxfer \
    && apk del build-base python3-dev openssl-dev libffi-dev \
    && rm /var/cache/apk/*
