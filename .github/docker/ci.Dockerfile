FROM nvidia/cuda:12.6.3-devel-ubuntu22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential git wget ca-certificates \
    python3 python3-pip \
    clang-tidy \
    zlib1g-dev libssl-dev libomp-dev libgmp-dev libntl-dev \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# CMake 3.28 (HEonGPU requires >= 3.26.4)
RUN wget -q https://ghfast.top/https://github.com/Kitware/CMake/releases/download/v3.28.3/cmake-3.28.3-linux-x86_64.tar.gz \
    && tar -C /usr/local --strip-components=1 -xzf cmake-3.28.3-linux-x86_64.tar.gz \
    && rm cmake-3.28.3-linux-x86_64.tar.gz

RUN pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple networkx pytest

# Go 1.24.0
RUN wget -q https://golang.google.cn/dl/go1.24.0.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz \
    && rm go1.24.0.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/root/go"
