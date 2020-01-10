FROM alpine:3.8.4

ARG OPENSSL_VERSION=1.0.2u-r0

RUN apk update && \
    apk add --no-cache openssl==${OPENSSL_VERSION} \
    curl && \
    rm -rf /var/cache/apk/*

ENTRYPOINT ["openssl"]