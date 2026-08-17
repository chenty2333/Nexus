# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG RUST_IMAGE=rust:1.95.0-slim-bookworm@sha256:6f9e63259f12e1e599296f5ecfed2bae46de4af0ee0525dd8b89c046e236d5c5

FROM ${RUST_IMAGE}

ARG GIT_PACKAGE_VERSION=1:2.39.5-0+deb12u3

LABEL org.opencontainers.image.title="Nexus verification environment" \
      org.opencontainers.image.description="Pinned Rust tools for the current Nexus CSER core"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends "git=${GIT_PACKAGE_VERSION}" \
    && test "$(git --version)" = 'git version 2.39.5' \
    && rm -rf /var/lib/apt/lists/*

RUN rustup component add --toolchain 1.95.0 clippy rustfmt \
    && rustup target add --toolchain 1.95.0 x86_64-unknown-none

# Fetch both locked dependency graphs once while building the image. Cargo
# deliberately rewrites a workspace lockfile when it is copied beside a
# standalone member manifest, so preserve the root workspace topology here.
# Runtime verification is offline: a dependency change therefore requires an
# updated lockfile and a rebuilt image.
COPY Cargo.lock /tmp/nexus-locks/Cargo.lock
COPY tools/xtask/Cargo.lock /tmp/nexus-locks/xtask.Cargo.lock
COPY Cargo.toml /tmp/nexus-inputs/root.Cargo.toml
COPY crates/cser-core/Cargo.toml /tmp/nexus-inputs/cser-core.Cargo.toml
COPY crates/cser-model/Cargo.toml /tmp/nexus-inputs/cser-model.Cargo.toml
COPY tools/xtask/Cargo.toml /tmp/nexus-inputs/xtask.Cargo.toml
COPY .cargo/config.toml /tmp/nexus-inputs/cargo-config.toml
RUN --mount=type=bind,source=.,target=/tmp/nexus-workspace,readonly \
    cmp /tmp/nexus-locks/Cargo.lock /tmp/nexus-workspace/Cargo.lock \
    && cmp /tmp/nexus-locks/xtask.Cargo.lock /tmp/nexus-workspace/tools/xtask/Cargo.lock \
    && cmp /tmp/nexus-inputs/root.Cargo.toml /tmp/nexus-workspace/Cargo.toml \
    && cmp /tmp/nexus-inputs/cser-core.Cargo.toml \
        /tmp/nexus-workspace/crates/cser-core/Cargo.toml \
    && cmp /tmp/nexus-inputs/cser-model.Cargo.toml \
        /tmp/nexus-workspace/crates/cser-model/Cargo.toml \
    && cmp /tmp/nexus-inputs/xtask.Cargo.toml \
        /tmp/nexus-workspace/tools/xtask/Cargo.toml \
    && cmp /tmp/nexus-inputs/cargo-config.toml \
        /tmp/nexus-workspace/.cargo/config.toml \
    && cargo fetch --locked --manifest-path /tmp/nexus-workspace/Cargo.toml \
    && cargo fetch --locked --manifest-path /tmp/nexus-workspace/tools/xtask/Cargo.toml \
    && rm -rf /tmp/nexus-locks /tmp/nexus-inputs \
    && chmod -R a+rwX /usr/local/cargo

ENV CARGO_NET_OFFLINE=true

WORKDIR /work
