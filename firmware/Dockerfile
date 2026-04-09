# Dockerfile for Rust-based 2026 eCTF firmware
# Adapts the build environment for embedded Rust development targeting ARM microcontrollers

FROM ubuntu:24.04

LABEL version="0.2"
LABEL description="HSM Docker Container for the 2026 eCTF"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

# Install Requisite Packages
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    wget \
    build-essential \
    unzip \
    curl
RUN pip3 install --break-system-packages cryptography


# # Install MSPM0 SDK (for header files and low-level bindings)
# RUN wget https://github.com/TexasInstruments/mspm0-sdk/archive/refs/tags/mspm0_sdk_2_06_00_05.zip && \
#     unzip mspm0_sdk_2_06_00_05.zip -d /opt && \
#     rm -f -r mspm0_sdk_2_06_00_05.zip ${MSPM0_SDK_INSTALL_DIR}/docs ${MSPM0_SDK_INSTALL_DIR}/examples

# # Install TI-Clang (needed for some low-level tools, even if Rust is primary)
# RUN if [ $(uname -m) = "x86_64" ]; then \
#     wget -O ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-ayxs93eZNN/4.0.3.LTS/ti_cgt_armllvm_4.0.3.LTS_linux-x64_installer.bin --ca-certificate=SSLCerts/mitre-chain.pem; \
#     elif [ $(uname -m) = "aarch64" ] || [ $(uname -m) = "arm64" ]; then \
#     wget -O ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-ayxs93eZNN/4.0.3.LTS/ti_cgt_armllvm_4.0.3.LTS_linux-arm64_installer.bin --ca-certificate=SSLCerts/mitre-chain.pem; \
#     else \
#     $(false); \
#     fi && \
#     chmod +x ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin && \
#     ./ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin --mode unattended --prefix /opt && \
#     rm -f ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install ARM targets for embedded development
# Add thumbv6m-none-eabi for MSPM0 (Cortex-M0+)
RUN rustup target add thumbv6m-none-eabi thumbv7m-none-eabi
RUN rustup component add llvm-tools-preview

# Install cargo-binutils for objcopy/other embedded tools
RUN cargo install cargo-binutils

WORKDIR /hsm

# Copy only the dependency manifest first so Docker can cache dependency downloads.
COPY Cargo.toml Cargo.lock ./
COPY src/main.rs ./src/main.rs

# Prefetch Rust dependencies (including git dependencies) for embedded targets.
RUN cargo fetch --locked --manifest-path /hsm/Cargo.toml --target thumbv6m-none-eabi --target thumbv7m-none-eabi

# For Rust projects, you might use a build script (build.rs or custom build.sh)
# Adjust the ENTRYPOINT as needed if you have a build script
ENTRYPOINT ["bash", "/hsm/build.sh"]