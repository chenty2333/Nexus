#!/usr/bin/env bash
set -euo pipefail

source_file=${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/src/personality/linux_fs.rs}

fail() {
    echo "runtime filesystem production source assertion: FAIL: $*" >&2
    exit 1
}

[[ -f $source_file && ! -L $source_file ]] ||
    fail "implementation source is not a regular non-symlink file: $source_file"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
legacy_dispatch=$work/legacy-dispatch.rs
legacy_finish=$work/legacy-finish.rs

start=$(grep -nF 'fn dispatch_first_executable_pread(' "$source_file" |
    cut -d: -f1 || true)
end=$(grep -nF 'fn dispatch(&self, descriptor: SyscallDescriptor)' "$source_file" |
    cut -d: -f1 || true)
[[ $start =~ ^[0-9]+$ && $end =~ ^[0-9]+$ && $start -lt $end ]] ||
    fail 'legacy dispatch source boundary is missing or ambiguous'
sed -n "${start},$((end - 1))p" "$source_file" >"$legacy_dispatch"
[[ -s $legacy_dispatch ]] || fail 'legacy dispatch source boundary is empty'

start=$(grep -nF 'fn finish_first_executable_read(' "$source_file" |
    cut -d: -f1 || true)
end=$(grep -nF 'fn commit(&mut self, registered: &RegisteredEffect, result: i64)' \
    "$source_file" | cut -d: -f1 || true)
[[ $start =~ ^[0-9]+$ && $end =~ ^[0-9]+$ && $start -lt $end ]] ||
    fail 'legacy finish source boundary is missing or ambiguous'
sed -n "${start},$((end - 1))p" "$source_file" >"$legacy_finish"
[[ -s $legacy_finish ]] || fail 'legacy finish source boundary is empty'

line_of() {
    local pattern=$1
    local line
    line=$(grep -nF -m1 "$pattern" "$legacy_dispatch" | cut -d: -f1 || true)
    [[ -n $line ]] || fail "missing source transition: $pattern"
    printf '%s\n' "$line"
}

fd_validation=$(line_of 'state.fds.get(&3) != Some(&FdKind::Executable)')
capture=$(line_of 'let registered = state.capture(descriptor, vec![PROCESS_RESOURCE]);')
fd_invariant=$(line_of 'assert_eq!(state.fds.get(&3), Some(&FdKind::Executable));')
begin=$(line_of 'let prepared = state.begin_first_executable_read(&registered, descriptor);')
payload=$(line_of 'let bytes = RUNTIME_FS_ELF[start..end].to_vec();')
finish=$(line_of 'let receipt = state.finish_first_executable_read(prepared, descriptor, &bytes);')
personality_commit=$(line_of 'let commit = state.commit(&registered, result);')

((fd_validation < capture && capture < fd_invariant && fd_invariant < begin && begin < payload &&
    payload < finish && finish < personality_commit)) ||
    fail 'validate/capture/invariant/prepare/read/finish/personality-commit order changed'

if grep -Fq '.commit(BLOCK_V1' "$legacy_finish"; then
    fail 'deterministic Phase-2 BlockRequest acquired a device CommitReceipt'
fi
grep -Fq 'TerminalRequest::aborted(-125)' "$legacy_finish" ||
    fail 'preparation-only BlockRequest abort is missing'

for class in QUEUE_SLOT_CREDIT PINNED_PAGE_CREDIT DMA_MAPPING_CREDIT; do
    if grep -Fq "CreditCharge::new($class" "$legacy_finish"; then
        fail "$class is charged without a real device owner"
    fi
done

grep -Fq 'fresh cohort solely for the negative oracle' "$source_file" ||
    fail 'fresh-registry helper lost its negative-only boundary'
grep -Fq 'foreign_registry_receipt=CommitConflict foreign_receipt_accepted=false' "$source_file" ||
    fail 'fresh-registry substitution rejection receipt is missing'
grep -Fq 'crash_injection=registry_domain real_user_service_crash=false' "$source_file" ||
    fail 'bounded crash mechanism boundary is missing'
grep -Fq 'device_commit=false avail_idx_release=false' "$source_file" ||
    fail 'block-preparation non-claim is missing'

echo 'runtime filesystem production source assertions: PASS input_validation_before_capture=true capture_before_payload=true shared_registry=true registry_domain_crash=true real_user_service_crash=false block_preparation_only=true device_commit=false device_credits_held=0 fresh_registry_negative_only=true'
