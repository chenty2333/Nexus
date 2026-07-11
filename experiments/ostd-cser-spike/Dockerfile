ARG OSDK_IMAGE=asterinas/osdk:0.18.0-20260603@sha256:a7540bfcd262ae52471f86353a87663d91941958e503557863738d13de4aace3
FROM ${OSDK_IMAGE}

RUN rustup target add --toolchain nightly-2026-04-03 x86_64-unknown-none \
    && cargo install cargo-osdk --version 0.18.0 --locked

COPY Cargo.toml Cargo.lock rust-toolchain.toml /tmp/ostd-cser-fetch/
RUN mkdir -p /tmp/ostd-cser-fetch/src \
    && touch /tmp/ostd-cser-fetch/src/lib.rs \
    && cd /tmp/ostd-cser-fetch \
    && cargo fetch --locked --target x86_64-unknown-none

WORKDIR /work
