# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG OSDK_IMAGE=asterinas/osdk:0.18.0-20260603@sha256:a7540bfcd262ae52471f86353a87663d91941958e503557863738d13de4aace3
FROM ${OSDK_IMAGE}

RUN rustup target add --toolchain nightly-2026-04-03 x86_64-unknown-none \
    && rustup component add --toolchain nightly-2026-04-03 rustfmt clippy \
    && cargo install cargo-osdk --version 0.18.0 --locked

# cargo-osdk's -Zbuild-std and generated runner packages have dependencies that
# a plain `cargo fetch --target` does not discover. Prime the real graph while
# the image is built, then make every mounted-workspace invocation offline.
COPY kernel/nexus-ostd/Cargo.toml \
    kernel/nexus-ostd/Cargo.lock \
    kernel/nexus-ostd/rust-toolchain.toml \
    kernel/nexus-ostd/OSDK.toml \
    /tmp/nexus-ostd-inputs/
COPY kernel/nexus-ostd/osdk-runner-base /tmp/nexus-ostd-inputs/osdk-runner-base
COPY kernel/nexus-ostd/userspace/personality /tmp/nexus-ostd-inputs/personality
COPY kernel/nexus-ostd/guest/linux-futex-core-personality-v1.S \
    kernel/nexus-ostd/guest/linux-futex-core-personality-v2.S \
    /tmp/nexus-ostd-inputs/guest/
COPY kernel/nexus-ostd/scripts/build-guest.sh \
    kernel/nexus-ostd/scripts/assert-linux-elf.sh \
    kernel/nexus-ostd/scripts/assert-dynamic-pie-artifacts.sh \
    kernel/nexus-ostd/scripts/check-fsbase-api.sh \
    kernel/nexus-ostd/scripts/check-scheduler-attempt.sh \
    kernel/nexus-ostd/scripts/build-round4.sh \
    kernel/nexus-ostd/scripts/build-round5.sh \
    /tmp/nexus-ostd-inputs/scripts/
COPY tests/guest/linux/sources/linux-hello/hello.S /tmp/nexus-ostd-inputs/linux-hello.S
COPY tests/guest/linux/sources/linux-dynamic-pie-smoke/dynamic_pie_smoke.S \
    /tmp/nexus-ostd-inputs/dynamic_pie_smoke.S
COPY tests/guest/linux/sources/linux-dynamic-pie-main/dynamic_pie_main.c \
    /tmp/nexus-ostd-inputs/dynamic_pie_main.c
COPY tests/guest/linux/sources/linux-dynamic-runtime-interp/dynamic_runtime_interp.c \
    /tmp/nexus-ostd-inputs/dynamic_runtime_interp.c
COPY tests/guest/linux/sources/linux-round4-futex-smoke/round4_futex_smoke.S \
    /tmp/nexus-ostd-inputs/round4_futex_smoke.S
COPY tests/guest/linux/adaptations/round4-futex-modern-requeue.patch \
    /tmp/nexus-ostd-inputs/round4-futex-modern-requeue.patch
COPY tests/guest/linux/sources/linux-round5-epoll-smoke/round5_epoll_smoke.S \
    /tmp/nexus-ostd-inputs/round5_epoll_smoke.S
COPY tests/guest/linux/adaptations/round5-epoll-linux-regular-file.patch \
    tests/guest/linux/adaptations/verify-round5-epoll-adaptation.sh \
    /tmp/nexus-ostd-inputs/round5/
RUN --mount=type=bind,source=kernel/nexus-ostd,target=/tmp/nexus-ostd-source,readonly \
    cmp /tmp/nexus-ostd-inputs/Cargo.toml /tmp/nexus-ostd-source/Cargo.toml \
    && cmp /tmp/nexus-ostd-inputs/Cargo.lock /tmp/nexus-ostd-source/Cargo.lock \
    && cmp /tmp/nexus-ostd-inputs/rust-toolchain.toml \
        /tmp/nexus-ostd-source/rust-toolchain.toml \
    && cmp /tmp/nexus-ostd-inputs/OSDK.toml /tmp/nexus-ostd-source/OSDK.toml \
    && diff -ru /tmp/nexus-ostd-inputs/osdk-runner-base \
        /tmp/nexus-ostd-source/osdk-runner-base \
    && diff -ru /tmp/nexus-ostd-inputs/personality \
        /tmp/nexus-ostd-source/userspace/personality \
    && cmp /tmp/nexus-ostd-inputs/guest/linux-futex-core-personality-v1.S \
        /tmp/nexus-ostd-source/guest/linux-futex-core-personality-v1.S \
    && cmp /tmp/nexus-ostd-inputs/guest/linux-futex-core-personality-v2.S \
        /tmp/nexus-ostd-source/guest/linux-futex-core-personality-v2.S \
    && cmp /tmp/nexus-ostd-inputs/scripts/build-guest.sh \
        /tmp/nexus-ostd-source/scripts/build-guest.sh \
    && cmp /tmp/nexus-ostd-inputs/scripts/assert-linux-elf.sh \
        /tmp/nexus-ostd-source/scripts/assert-linux-elf.sh \
    && cmp /tmp/nexus-ostd-inputs/scripts/assert-dynamic-pie-artifacts.sh \
        /tmp/nexus-ostd-source/scripts/assert-dynamic-pie-artifacts.sh \
    && cmp /tmp/nexus-ostd-inputs/scripts/check-fsbase-api.sh \
        /tmp/nexus-ostd-source/scripts/check-fsbase-api.sh \
    && cmp /tmp/nexus-ostd-inputs/scripts/check-scheduler-attempt.sh \
        /tmp/nexus-ostd-source/scripts/check-scheduler-attempt.sh \
    && cmp /tmp/nexus-ostd-inputs/scripts/build-round4.sh \
        /tmp/nexus-ostd-source/scripts/build-round4.sh \
    && cmp /tmp/nexus-ostd-inputs/scripts/build-round5.sh \
        /tmp/nexus-ostd-source/scripts/build-round5.sh \
    && rm -rf /work \
    && cp -a /tmp/nexus-ostd-source /work \
    && mkdir -p /work/target/osdk \
    && cp -a /tmp/nexus-ostd-inputs/osdk-runner-base \
        /work/target/osdk/nexus-kernel-run-base \
    && cd /work \
    && NEXUS_LINUX_HELLO_SOURCE=/tmp/nexus-ostd-inputs/linux-hello.S \
        NEXUS_DYNAMIC_PIE_LAUNCHER_SOURCE=/tmp/nexus-ostd-inputs/dynamic_pie_smoke.S \
        NEXUS_DYNAMIC_PIE_MAIN_SOURCE=/tmp/nexus-ostd-inputs/dynamic_pie_main.c \
        NEXUS_DYNAMIC_PIE_INTERP_SOURCE=/tmp/nexus-ostd-inputs/dynamic_runtime_interp.c \
        NEXUS_ROUND4_FUTEX_SOURCE=/tmp/nexus-ostd-inputs/round4_futex_smoke.S \
        NEXUS_ROUND4_FUTEX_PATCH=/tmp/nexus-ostd-inputs/round4-futex-modern-requeue.patch \
        NEXUS_ROUND5_EPOLL_SOURCE=/tmp/nexus-ostd-inputs/round5_epoll_smoke.S \
        NEXUS_ROUND5_EPOLL_PATCH=/tmp/nexus-ostd-inputs/round5/round5-epoll-linux-regular-file.patch \
        NEXUS_ROUND5_EPOLL_ORACLE=/tmp/nexus-ostd-inputs/round5/verify-round5-epoll-adaptation.sh \
        bash scripts/build-guest.sh \
    && cargo osdk check --locked \
    && bash scripts/check-fsbase-api.sh \
    && bash scripts/check-scheduler-attempt.sh \
    && cargo osdk build \
    && cmp /tmp/nexus-ostd-inputs/Cargo.lock /work/Cargo.lock \
    && diff -ru /tmp/nexus-ostd-inputs/osdk-runner-base \
        /work/target/osdk/nexus-kernel-run-base \
    && rm -rf /work /tmp/nexus-ostd-inputs

# The upstream image stores its toolchain and firmware below a mode-0700
# /root. Make only the traversal/read bits and Cargo's small lock databases
# available to the invoking host UID. Moving or recursively chmodding the
# multi-gigabyte toolchain would copy it into a new image layer.
RUN chmod 0755 /root \
    && find /root/.cargo /root/.rustup -type d ! -perm -0005 -exec chmod o+rx {} + \
    && find /root/.cargo /root/.rustup -type f ! -perm -0004 -exec chmod o+r {} + \
    && for lock in /root/.cargo/.package-cache /root/.cargo/.global-cache; do \
        if [ -e "$lock" ]; then chmod a+rw "$lock"; fi; \
    done

ENV CARGO_HOME=/root/.cargo \
    RUSTUP_HOME=/root/.rustup \
    CARGO_NET_OFFLINE=true \
    PATH=/root/.cargo/bin:/usr/local/grub/bin:/usr/local/qemu/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /work
