# erreur à la compilation

FROM alpine:3.10

ARG OPENSSL_VERSION=1.1.0l

RUN apk update && \
    apk add --no-cache perl build-base && \
    rm -rf /var/cache/apk/*

RUN wget https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz -O - | tar -xz

WORKDIR /openssl-${OPENSSL_VERSION}

RUN ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl && \
    make && \
    make install

#ENTRYPOINT ["openssl"]