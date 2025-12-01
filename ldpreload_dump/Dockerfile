FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        crossbuild-essential-arm64 \
        gcc-aarch64-linux-gnu \
        g++-aarch64-linux-gnu \
        libc6-dev-arm64-cross \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY iolog.c /build/iolog.c
COPY Makefile /build/Makefile

# glibc 2.31 required...
RUN make

# Default command – just drop you into a shell if you run the image
CMD ["/bin/bash"]
