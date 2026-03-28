FROM ubuntu:24.04

LABEL version="0.1"
LABEL description="Rust-based HSM firmware build container for MSPM0"

ARG DEBIAN_FRONTEND=noninteractive
WORKDIR /root

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    python3 \
    make \
    wget \
    build-essential \
    unzip \
    curl \
    ca-certificates

ENV MSPM0_SDK_INSTALL_DIR=/opt/mspm0-sdk-mspm0_sdk_2_06_00_05
ENV TICLANG_ARMCOMPILER=/opt/ti-cgt-armllvm_4.0.3.LTS
ENV PATH=/root/.cargo/bin:${PATH}

RUN curl https://sh.rustup.rs -sSf | bash -s -- -y
RUN rustup target add thumbv6m-none-eabi

RUN wget https://github.com/TexasInstruments/mspm0-sdk/archive/refs/tags/mspm0_sdk_2_06_00_05.zip && \
    unzip mspm0_sdk_2_06_00_05.zip -d /opt && \
    rm -f -r mspm0_sdk_2_06_00_05.zip ${MSPM0_SDK_INSTALL_DIR}/docs ${MSPM0_SDK_INSTALL_DIR}/examples

RUN if [ $(uname -m) = "x86_64" ]; then \
    wget -O ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-ayxs93eZNN/4.0.3.LTS/ti_cgt_armllvm_4.0.3.LTS_linux-x64_installer.bin --ca-certificate=SSLCerts/mitre-chain.pem; \
    elif [ $(uname -m) = "aarch64" ] || [ $(uname -m) = "arm64" ]; then \
    wget -O ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin https://dr-download.ti.com/software-development/ide-configuration-compiler-or-debugger/MD-ayxs93eZNN/4.0.3.LTS/ti_cgt_armllvm_4.0.3.LTS_linux-arm64_installer.bin --ca-certificate=SSLCerts/mitre-chain.pem; \
    else \
    $(false); \
    fi && \
    chmod +x ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin && \
    ./ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin --mode unattended --prefix /opt && \
    rm -f ti_cgt_armllvm_4.0.3.LTS_linux_installer.bin

WORKDIR /hsm
ENTRYPOINT ["bash", "/hsm/build.sh"]
