set dotenv-load := false

default:
  @just --list

fmt:
  cargo fmt --all

lint:
  cargo xlint

test:
  cargo xtest

test-all:
  cargo test --workspace

# Loom runs are slower; enable only when you need concurrency-model checking.
loom:
  cargo test -p axle-sync --features loom

