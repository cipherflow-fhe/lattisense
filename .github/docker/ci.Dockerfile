FROM nvidia/cuda:12.6.3-devel-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential cmake git wget ca-certificates \
    python3 python3-pip \
    clang-tidy \
    zlib1g-dev libssl-dev libomp-dev \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install networkx pytest

RUN wget -q https://go.dev/dl/go1.24.0.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz \
    && rm go1.24.0.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/root/go"
