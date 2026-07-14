# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG JAVA_IMAGE=eclipse-temurin:21.0.8_9-jre-jammy@sha256:cddd554e8d69b48b46e8b0c9d1ce72ae5fe8d84819dcdb7131328531e9cc100b
ARG RUST_IMAGE=rust:1.95.0-slim-bookworm@sha256:6f9e63259f12e1e599296f5ecfed2bae46de4af0ee0525dd8b89c046e236d5c5

FROM ${JAVA_IMAGE} AS java

FROM ${RUST_IMAGE}

ARG TLA2TOOLS_VERSION=1.8.0
# Official v1.8.0 release asset 476406882, published 2026-07-14 from the
# verified upstream revision 227f61b983d0203a06db8184da45aed421e8f1b8.
ARG TLA2TOOLS_SHA256=150b0294c3d407c15f0c971351ccd4ae8c6d885397546dff87871a14be2b4ee4
ARG GIT_PACKAGE_VERSION=1:2.39.5-0+deb12u3

LABEL org.opencontainers.image.title="Nexus verification environment" \
      org.opencontainers.image.description="Pinned Rust and TLA+ tools for the Nexus CSER model"

COPY --from=java /opt/java/openjdk /opt/java/openjdk

RUN apt-get update \
    && apt-get install --yes --no-install-recommends "git=${GIT_PACKAGE_VERSION}" \
    && test "$(git --version)" = 'git version 2.39.5' \
    && rm -rf /var/lib/apt/lists/*

ENV JAVA_HOME=/opt/java/openjdk \
    PATH=/opt/java/openjdk/bin:${PATH} \
    TLA2TOOLS_JAR=/opt/tla2tools/tla2tools.jar

RUN rustup component add --toolchain 1.95.0 clippy rustfmt \
    && rustup target add --toolchain 1.95.0 x86_64-unknown-none \
    && java -version

ADD --chmod=0444 --checksum=sha256:${TLA2TOOLS_SHA256} \
    https://github.com/tlaplus/tlaplus/releases/download/v${TLA2TOOLS_VERSION}/tla2tools.jar \
    /opt/tla2tools/tla2tools.jar
RUN chmod 0555 /opt/tla2tools

# Fetch both locked dependency graphs once while building the image. Cargo
# deliberately rewrites a workspace lockfile when it is copied beside a
# standalone member manifest, so preserve the root workspace topology here.
# Runtime verification is offline: a dependency change therefore requires an
# updated lockfile and a rebuilt image.
COPY Cargo.lock /tmp/nexus-locks/Cargo.lock
COPY tools/xtask/Cargo.lock /tmp/nexus-locks/xtask.Cargo.lock
COPY Cargo.toml /tmp/nexus-inputs/root.Cargo.toml
COPY crates/cser-model/Cargo.toml /tmp/nexus-inputs/cser-model.Cargo.toml
COPY crates/cser-transition-gates/Cargo.toml /tmp/nexus-inputs/cser-transition-gates.Cargo.toml
COPY tools/xtask/Cargo.toml /tmp/nexus-inputs/xtask.Cargo.toml
COPY .cargo/config.toml /tmp/nexus-inputs/cargo-config.toml
RUN --mount=type=bind,source=.,target=/tmp/nexus-workspace,readonly \
    cmp /tmp/nexus-locks/Cargo.lock /tmp/nexus-workspace/Cargo.lock \
    && cmp /tmp/nexus-locks/xtask.Cargo.lock /tmp/nexus-workspace/tools/xtask/Cargo.lock \
    && cmp /tmp/nexus-inputs/root.Cargo.toml /tmp/nexus-workspace/Cargo.toml \
    && cmp /tmp/nexus-inputs/cser-model.Cargo.toml \
        /tmp/nexus-workspace/crates/cser-model/Cargo.toml \
    && cmp /tmp/nexus-inputs/cser-transition-gates.Cargo.toml \
        /tmp/nexus-workspace/crates/cser-transition-gates/Cargo.toml \
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
