FROM ubuntu:latest

ARG OPENSSL_VERSION=1.1.0l

RUN apt update && \
    apt upgrade -y && \
    apt install -y wget perl build-essential

RUN wget https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz -O - | tar -xz

WORKDIR /openssl-${OPENSSL_VERSION}

ENV LD_LIBRARY_PATH=/usr/local/lib

RUN ./config && \
    make && \
    make install

ENTRYPOINT ["openssl"]