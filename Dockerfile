# ============================================================================
# LattiSense Docker Image
# ============================================================================
# Two-stage build: compile the SDK, then set up the development environment
# with source code, pre-built SDK, and compilation toolchain.
#
# Build command:
#   docker build -t lattisense .
# ============================================================================

# ============================================================================
# Stage 1: Builder - Compile the SDK
# ============================================================================
FROM ubuntu:22.04 AS builder

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
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
# Stage 2: Final image - Source code + pre-built SDK + toolchain
# ============================================================================
FROM builder

# Install development tools and Python dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    vim \
    gdb \
    && pip3 install networkx \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables for SDK
ENV LD_LIBRARY_PATH="/opt/lattisense/lib"
ENV CMAKE_PREFIX_PATH="/opt/lattisense/lib/cmake/LattiSense"
ENV PYTHONPATH="/opt/lattisense/share/lattisense/mega_ag_generator"

# Source code is already at /workspace/lattisense from builder stage
WORKDIR /workspace

# Copy project_template to workspace for easy access
RUN cp -r /opt/lattisense/share/lattisense/project_template /workspace/project_template

# Default command
CMD ["/bin/bash"]
