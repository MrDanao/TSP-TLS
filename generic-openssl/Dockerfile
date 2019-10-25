FROM alpine:latest

RUN apk update && \
    apk add --no-cache openssl \
    curl && \
    rm -rf /var/cache/apk/*

ENTRYPOINT ["openssl"]