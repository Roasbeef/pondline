# Pinned Linux x86_64 release builder for Pondline (ADR-003).
#
# Ubuntu 24.04 provides the glibc 2.39 baseline while keeping system OpenSSL
# 3.0 isolated from the release toolchain:
#   - OpenSSL 3.5.9 LTS in /opt/pondline-openssl (provides ML-KEM-1024 and
#     ML-DSA-65);
#   - Prebuilt Erlang/OTP 29.1.2 from Hex.pm's ubuntu-24.04 builds, with OTP's
#     `crypto` NIF (`lib/crypto/c_src`) recompiled against /opt/pondline-openssl
#     so compile-time OpenSSL >= 3.5 symbols (ML-KEM, ML-DSA) and runtime
#     libcrypto.so.3 match identically;
#   - Gleam 1.19.2, rebar3 3.27.0, Rust 1.98.1, patchelf and sqlite3.
#
# Build:
#   DOCKER_BUILDKIT=1 docker build --platform=linux/amd64 \
#     -f docker/release-builder.Dockerfile -t pondline-release-builder:local .

FROM ubuntu:24.04

ARG OPENSSL_VERSION=3.5.9
ARG OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a

ARG OTP_VERSION=29.1.2
ARG OTP_BIN_SHA256=2cfca446976fc61962585a1c77e5d11ddb6f5fed83e84668a2c4acfaad60d22e
ARG OTP_SRC_SHA256=c79966661e35fe4aff8ec003db63682e3b33b10b672220d51bf93c0a9244b049

ARG GLEAM_VERSION=1.19.2
ARG GLEAM_AMD64_SHA256=2ba2afb66ca9f6dcc01a4a6e9169b6942963bad6483bec9571ddc078cfe6f41f

ARG REBAR3_VERSION=3.27.0
ARG REBAR3_SHA256=af85aab41f9fd74bdd6341ebdf6fe9c88077aab9f8eac82371583fa02f2b0bdf

ARG RUST_TOOLCHAIN=1.98.1

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update -qq && apt-get install -y --no-install-recommends \
    autoconf \
    build-essential \
    ca-certificates \
    curl \
    file \
    git \
    libncurses-dev \
    patchelf \
    perl \
    pkg-config \
    procps \
    sqlite3 \
    xz-utils \
    zlib1g-dev \
  && rm -rf /var/lib/apt/lists/*

# --- OpenSSL >= 3.5 (isolated under /opt/pondline-openssl) -------------------
RUN set -eux; \
  curl -fsSL -o /tmp/openssl.tar.gz \
    "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz"; \
  echo "${OPENSSL_SHA256}  /tmp/openssl.tar.gz" | sha256sum -c -; \
  mkdir -p /tmp/openssl-src; \
  tar -xzf /tmp/openssl.tar.gz -C /tmp/openssl-src --strip-components=1; \
  cd /tmp/openssl-src; \
  ./Configure \
    --prefix=/opt/pondline-openssl \
    --libdir=lib \
    --openssldir=/opt/pondline-openssl/ssl \
    shared \
    no-tests \
    no-docs \
    "-Wl,-rpath,/opt/pondline-openssl/lib"; \
  make -j"$(nproc)"; \
  make install_sw; \
  rm -rf /tmp/openssl.tar.gz /tmp/openssl-src

# --- Erlang/OTP 29.1.2 + crypto NIF compiled against OpenSSL 3.5.9 -----------
RUN set -eux; \
  curl -fsSL -o /tmp/otp-bin.tar.gz \
    "https://builds.hex.pm/builds/otp/ubuntu-24.04/OTP-${OTP_VERSION}.tar.gz"; \
  echo "${OTP_BIN_SHA256}  /tmp/otp-bin.tar.gz" | sha256sum -c -; \
  mkdir -p /usr/local/otp; \
  tar -xzf /tmp/otp-bin.tar.gz -C /usr/local/otp --strip-components=1; \
  (cd /usr/local/otp && ./Install -minimal /usr/local/otp); \
  for bin in /usr/local/otp/bin/*; do ln -sf "$bin" "/usr/local/bin/$(basename "$bin")"; done; \
  curl -fsSL -o /tmp/otp-src.tar.gz \
    "https://github.com/erlang/otp/releases/download/OTP-${OTP_VERSION}/otp_src_${OTP_VERSION}.tar.gz"; \
  echo "${OTP_SRC_SHA256}  /tmp/otp-src.tar.gz" | sha256sum -c -; \
  mkdir -p /tmp/otp-src; \
  tar -xzf /tmp/otp-src.tar.gz -C /tmp/otp-src --strip-components=1 \
    "otp_src_${OTP_VERSION}/lib/crypto"; \
  ERTS_INCLUDE=$(echo /usr/local/otp/erts-*/include); \
  CRYPTO_PRIV=$(echo /usr/local/otp/lib/crypto-*/priv/lib); \
  CSRC="/tmp/otp-src/lib/crypto/c_src"; \
  SRCS=$(find "$CSRC" -maxdepth 1 -name '*.c' ! -name 'otp_test_engine.c' ! -name 'crypto_callback.c'); \
  gcc -O2 -fPIC -shared \
    -D_GNU_SOURCE -D_THREAD_SAFE -D_REENTRANT -DPOSIX_THREADS \
    -DSIZEOF_VOID_P=8 \
    -DHAVE_OPENSSL_CRYPTO_MEMCMP \
    -DHAVE_DYNAMIC_CRYPTO_LIB \
    -DDISABLE_EVP_DH=0 \
    -DDISABLE_EVP_HMAC=0 \
    -I"$ERTS_INCLUDE" \
    -I"$CSRC" \
    -I/opt/pondline-openssl/include \
    $SRCS \
    -L/opt/pondline-openssl/lib \
    -Wl,-rpath,/opt/pondline-openssl/lib \
    -lcrypto -ldl \
    -o "$CRYPTO_PRIV/crypto.so"; \
  gcc -O2 -fPIC -shared \
    -D_GNU_SOURCE -DSIZEOF_VOID_P=8 \
    -I"$ERTS_INCLUDE" \
    -I"$CSRC" \
    -I/opt/pondline-openssl/include \
    "$CSRC/crypto_callback.c" \
    -o "$CRYPTO_PRIV/crypto_callback.so"; \
  CRYPTO_EBIN=$(echo /usr/local/otp/lib/crypto-*/ebin); \
  erlc -I /tmp/otp-src/lib/crypto/include -o "$CRYPTO_EBIN" /tmp/otp-src/lib/crypto/src/*.erl; \
  rm -f "$CRYPTO_PRIV/otp_test_engine.so"; \
  rm -rf /tmp/otp-bin.tar.gz /tmp/otp-src.tar.gz /tmp/otp-src

# --- Gleam & rebar3 ----------------------------------------------------------
RUN set -eux; \
  curl -fsSL -o /tmp/gleam.tar.gz \
    "https://github.com/gleam-lang/gleam/releases/download/v${GLEAM_VERSION}/gleam-v${GLEAM_VERSION}-x86_64-unknown-linux-musl.tar.gz"; \
  echo "${GLEAM_AMD64_SHA256}  /tmp/gleam.tar.gz" | sha256sum -c -; \
  tar -xzf /tmp/gleam.tar.gz -C /usr/local/bin gleam; \
  chmod +x /usr/local/bin/gleam; \
  rm -f /tmp/gleam.tar.gz; \
  curl -fsSL -o /usr/local/bin/rebar3 \
    "https://github.com/erlang/rebar3/releases/download/${REBAR3_VERSION}/rebar3"; \
  echo "${REBAR3_SHA256}  /usr/local/bin/rebar3" | sha256sum -c -; \
  chmod +x /usr/local/bin/rebar3

# --- Rust toolchain for native/pondline-tor ----------------------------------
RUN curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}"
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /work
