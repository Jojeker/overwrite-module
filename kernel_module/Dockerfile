FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive \
    ARCH=arm64 \
    CROSS_COMPILE=aarch64-linux-gnu-

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        bc \
        kmod \
        cpio \
        flex \
        bison \
        libssl-dev \
        libelf-dev \
        libncurses5-dev \
        wget \
        ca-certificates \
        gcc-aarch64-linux-gnu \
        git && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Makefile .
COPY overwrite.c .
COPY README.md .
COPY kernel_config.txt .

RUN make all

