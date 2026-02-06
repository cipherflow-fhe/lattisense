# ============================================================================
# LattiSense Docker Image
# ============================================================================
# Multi-stage build for two image variants:
#   - release: Image with pre-built SDK and compilation toolchain (~800MB)
#   - dev: Full development environment with toolchain, Go, and source (~2.5GB)
#
# Build commands:
#   docker build --target release -t lattisense:release .
#   docker build --target dev -t lattisense:dev .
# ============================================================================

# ============================================================================
# Stage 1: Builder - Compile the SDK
# ============================================================================
FROM ubuntu:22.04 AS builder

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    wget \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.24.0 (required for Lattigo cryptography library)
RUN wget -q https://go.dev/dl/go1.24.0.linux-amd64.tar.gz \
    && tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz \
    && rm go1.24.0.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/root/go"

# Copy source code
WORKDIR /workspace
COPY . /workspace/lattisense

# Build and install SDK
WORKDIR /workspace/lattisense
RUN mkdir -p build && cd build \
    && cmake .. -DCMAKE_INSTALL_PREFIX=/opt/lattisense \
    && make -j$(nproc) install

# ============================================================================
# Stage 2: Release - Image with SDK and compilation toolchain
# ============================================================================
FROM ubuntu:22.04 AS release

ENV DEBIAN_FRONTEND=noninteractive

# Install compilation toolchain and Python dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    python3 \
    python3-pip \
    && pip3 install networkx \
    && rm -rf /var/lib/apt/lists/*

# Copy pre-built SDK from builder
COPY --from=builder /opt/lattisense /opt/lattisense

# Set environment variables for SDK
ENV LD_LIBRARY_PATH="/opt/lattisense/lib:${LD_LIBRARY_PATH}"
ENV CMAKE_PREFIX_PATH="/opt/lattisense/lib/cmake/LattiSense:${CMAKE_PREFIX_PATH}"
ENV PYTHONPATH="/opt/lattisense/share/lattisense/mega_ag_generator:${PYTHONPATH}"

WORKDIR /workspace

# Copy project_template to workspace for easy access
RUN cp -r /opt/lattisense/share/lattisense/project_template /workspace/project_template

# Default command
CMD ["/bin/bash"]

# ============================================================================
# Stage 3: Dev - Full development environment
# ============================================================================
FROM builder AS dev

# Install additional development tools and Python dependencies
RUN apt-get update && apt-get install -y \
    vim \
    gdb \
    python3-pip \
    && pip3 install networkx \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables for SDK
ENV LD_LIBRARY_PATH="/opt/lattisense/lib:${LD_LIBRARY_PATH}"
ENV CMAKE_PREFIX_PATH="/opt/lattisense/lib/cmake/LattiSense:${CMAKE_PREFIX_PATH}"
ENV PYTHONPATH="/opt/lattisense/share/lattisense/mega_ag_generator:${PYTHONPATH}"

# Source code is already at /workspace/lattisense from builder stage
WORKDIR /workspace

# Copy project_template to workspace for easy access
RUN cp -r /opt/lattisense/share/lattisense/project_template /workspace/project_template

# Default command
CMD ["/bin/bash"]
