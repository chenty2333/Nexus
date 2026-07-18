# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG JAVA_IMAGE=eclipse-temurin:21.0.8_9-jre-jammy@sha256:cddd554e8d69b48b46e8b0c9d1ce72ae5fe8d84819dcdb7131328531e9cc100b
ARG RUST_IMAGE=rust:1.95.0-slim-bookworm@sha256:6f9e63259f12e1e599296f5ecfed2bae46de4af0ee0525dd8b89c046e236d5c5

FROM ${JAVA_IMAGE} AS java

FROM ${RUST_IMAGE}

ARG TLA2TOOLS_SHA256=33de7da9ce1b7fffb9d1c184021178dbb051747be48504e65c584c423721a32e
ARG TLA2TOOLS_TLC_VERSION=2026.07.09.134028
ARG TLA2TOOLS_REVISION_SHORT=227f61b
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

COPY --chmod=0444 third_party/tlaplus/1.8.0-227f61b/tla2tools-227f61b.jar \
    /opt/tla2tools/tla2tools.jar
COPY --chmod=0444 third_party/tlaplus/1.8.0-227f61b/SHA256SUMS \
    third_party/tlaplus/1.8.0-227f61b/PROVENANCE.json \
    third_party/tlaplus/1.8.0-227f61b/LICENSE.upstream \
    /opt/tla2tools/
RUN echo "${TLA2TOOLS_SHA256}  /opt/tla2tools/tla2tools.jar" | sha256sum -c - \
    && version_output=$(java -cp /opt/tla2tools/tla2tools.jar tlc2.TLC -version 2>&1 || true) \
    && version_line=$(printf '%s\n' "$version_output" | sed -n '/./{p;q;}') \
    && test "$version_line" = \
        "TLC2 Version ${TLA2TOOLS_TLC_VERSION} (rev: ${TLA2TOOLS_REVISION_SHORT})" \
    && chmod 0555 /opt/tla2tools

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
COPY crates/nexus-effect-peer/Cargo.toml /tmp/nexus-inputs/nexus-effect-peer.Cargo.toml
COPY crates/nexus-portal-abi/Cargo.toml /tmp/nexus-inputs/nexus-portal-abi.Cargo.toml
COPY crates/nexus-supervisor/Cargo.toml /tmp/nexus-inputs/nexus-supervisor.Cargo.toml
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
    && cmp /tmp/nexus-inputs/nexus-effect-peer.Cargo.toml \
        /tmp/nexus-workspace/crates/nexus-effect-peer/Cargo.toml \
    && cmp /tmp/nexus-inputs/nexus-portal-abi.Cargo.toml \
        /tmp/nexus-workspace/crates/nexus-portal-abi/Cargo.toml \
    && cmp /tmp/nexus-inputs/nexus-supervisor.Cargo.toml \
        /tmp/nexus-workspace/crates/nexus-supervisor/Cargo.toml \
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
