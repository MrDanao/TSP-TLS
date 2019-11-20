FROM alpine:3.10.3

ARG OPENSSL_VERSION=1.1.1d-r0

RUN apk update && \
    apk add --no-cache openssl==${OPENSSL_VERSION} \
    curl && \
    rm -rf /var/cache/apk/*

ENTRYPOINT ["openssl"]