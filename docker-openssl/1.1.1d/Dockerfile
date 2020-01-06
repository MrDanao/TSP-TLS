FROM alpine:3.11

ARG OPENSSL_VERSION=1.1.1d-r3

RUN apk update && \
    apk add --no-cache openssl==${OPENSSL_VERSION} \
    curl && \
    rm -rf /var/cache/apk/*

ENTRYPOINT ["openssl"]