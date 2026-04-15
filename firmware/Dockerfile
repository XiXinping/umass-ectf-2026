# Dockerfile for building the HSM firmware. 
# This container is used in the build process and should contain all necessary
# tools and dependencies to compile the firmware for the MSPM0 microcontroller.

FROM ubuntu:24.04

LABEL version="0.2"
LABEL description="HSM Docker Container for the 2026 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Necessary Packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    wget \
    build-essential \
    unzip \
    curl
RUN pip3 install --break-system-packages cryptography

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install thumbv6m-none-eabi target and llvm tools 
RUN rustup target add thumbv6m-none-eabi
RUN rustup component add llvm-tools-preview

# Install cargo-binutils for rust-objcopy
RUN cargo install cargo-binutils

WORKDIR /hsm

# Copy dependency manifest and source code for prefetching dependencies. 
# This helps speed up subsequent builds by caching the dependencies layer.
COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/

# Fetch Rust dependencies for the thumbv6m-none-eabi target
RUN cargo fetch --locked --manifest-path /hsm/Cargo.toml --target thumbv6m-none-eabi

# Set the build script as the entrypoint for the container
ENTRYPOINT ["bash", "/hsm/build.sh"]