#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

patched_root=${NEXUS_OSTD_PATCHED_ROOT:-/opt/nexus-ostd/ostd-0.18.0}
if [[ -f $patched_root/src/arch/x86/cpu/context/mod.rs ]]; then
    context_file=$patched_root/src/arch/x86/cpu/context/mod.rs
else
    context_file=$(find "${CARGO_HOME:-/root/.cargo}/registry/src" \
        -path '*/ostd-0.18.0/src/arch/x86/cpu/context/mod.rs' -print -quit)
fi
if [[ -z ${context_file:-} || ! -f $context_file ]]; then
    echo 'ostd 0.18.0 x86 context source is unavailable' >&2
    exit 1
fi

cpu_mod=${context_file%/context/mod.rs}/mod.rs
grep -Eq '^pub[[:space:]]+mod[[:space:]]+context;' "$cpu_mod" || {
    echo 'OSTD x86 cpu::context is no longer public; re-audit the TLS boundary' >&2
    exit 1
}

fsbase_block=$(sed -n '/^pub struct FsBase/,/^\/\/\/ The user-mode GS base register\./p' "$context_file")
for pattern in \
    'pub struct FsBase(usize);' \
    'pub fn new(addr: usize) -> Self' \
    'pub fn addr(&self) -> usize' \
    'pub fn save(&mut self)' \
    'rdfsbase()' \
    'pub fn load(&self)' \
    'wrfsbase(self.0 as u64)'; do
    grep -Fq "$pattern" <<<"$fsbase_block" || {
        echo "OSTD FsBase API changed at: $pattern" >&2
        exit 1
    }
done

user_context_block=$(sed -n '/^pub struct UserContext {/,/^}/p' "$context_file")
if grep -Eqi 'fs[_ ]?base|FsBase' <<<"$user_context_block"; then
    echo 'OSTD UserContext gained FS-base ownership; re-audit task lifecycle integration' >&2
    exit 1
fi
grep -Fq 'user_context: RawUserContext' <<<"$user_context_block" || {
    echo 'OSTD UserContext representation changed; re-audit the FS-base boundary' >&2
    exit 1
}

echo 'FSBASE source probe: PASS public_explicit_load_save=true user_context_owns_fsbase=false runtime_task_lifecycle=not_observed ostd=0.18.0 source=compiled-tree'
