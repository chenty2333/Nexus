#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

launcher_source=${1:?usage: assert-dynamic-pie-artifacts.sh LAUNCHER_SOURCE MAIN_SOURCE INTERP_SOURCE LAUNCHER_ELF MAIN_ELF INTERP_ELF}
main_source=${2:?usage: assert-dynamic-pie-artifacts.sh LAUNCHER_SOURCE MAIN_SOURCE INTERP_SOURCE LAUNCHER_ELF MAIN_ELF INTERP_ELF}
interp_source=${3:?usage: assert-dynamic-pie-artifacts.sh LAUNCHER_SOURCE MAIN_SOURCE INTERP_SOURCE LAUNCHER_ELF MAIN_ELF INTERP_ELF}
launcher_elf=${4:?usage: assert-dynamic-pie-artifacts.sh LAUNCHER_SOURCE MAIN_SOURCE INTERP_SOURCE LAUNCHER_ELF MAIN_ELF INTERP_ELF}
main_elf=${5:?usage: assert-dynamic-pie-artifacts.sh LAUNCHER_SOURCE MAIN_SOURCE INTERP_SOURCE LAUNCHER_ELF MAIN_ELF INTERP_ELF}
interp_elf=${6:?usage: assert-dynamic-pie-artifacts.sh LAUNCHER_SOURCE MAIN_SOURCE INTERP_SOURCE LAUNCHER_ELF MAIN_ELF INTERP_ELF}

fail() {
    echo "dynamic PIE artifact assertion failed: $*" >&2
    exit 1
}

require_regular_file() {
    local path=$1
    [[ -f "$path" && ! -L "$path" ]] || fail "not a regular file: $path"
}

assert_sha256() {
    local path=$1
    local expected=$2
    local description=$3
    local actual

    actual=$(sha256sum "$path" | cut -d ' ' -f1)
    [[ "$actual" == "$expected" ]] || fail "$description SHA mismatch: got $actual, expected $expected"
}

assert_header() {
    local file=$1
    local type=$2
    local entry=$3
    local description=$4
    local header
    local actual_entry

    header=$(readelf -hW "$file")
    for pattern in \
        'Class:.*ELF64' \
        'Data:.*little endian' \
        "Type:.*$type" \
        'Machine:.*X86-64'; do
        grep -Eq "$pattern" <<<"$header" || fail "$description header does not match $pattern"
    done
    actual_entry=$(awk -F: '/Entry point address:/ { gsub(/[[:space:]]/, "", $2); print $2 }' <<<"$header")
    [[ "$actual_entry" == "$entry" ]] || fail "$description entry is $actual_entry, expected $entry"
}

program_count() {
    local programs=$1
    local kind=$2
    awk -v kind="$kind" '$1 == kind { count++ } END { print count + 0 }' <<<"$programs"
}

assert_program_count() {
    local programs=$1
    local kind=$2
    local expected=$3
    local description=$4
    local actual

    actual=$(program_count "$programs" "$kind")
    [[ "$actual" == "$expected" ]] || fail "$description has $actual $kind headers, expected $expected"
}

assert_no_wx_or_exec_stack() {
    local programs=$1
    local description=$2

    if grep -Eq '^[[:space:]]*LOAD.*W.*E' <<<"$programs"; then
        fail "$description contains a writable executable PT_LOAD"
    fi
    if grep -Eq '^[[:space:]]*GNU_STACK.*E' <<<"$programs"; then
        fail "$description requests an executable stack"
    fi
}

assert_no_runtime_link_dependencies() {
    local file=$1
    local description=$2
    local dynamic
    local undefined

    if ! grep -Fq 'There are no relocations in this file.' < <(readelf -rW "$file"); then
        fail "$description contains runtime relocations"
    fi
    undefined=$(nm -u "$file")
    [[ -z "$undefined" ]] || fail "$description contains undefined symbols: $undefined"
    dynamic=$(readelf -dW "$file")
    if grep -Eq '\((NEEDED|RPATH|RUNPATH|REL|RELA|RELSZ|RELASZ|JMPREL|PLTGOT|TEXTREL)\)' <<<"$dynamic"; then
        fail "$description contains an unexpected runtime-link dependency or relocation table"
    fi
}

assert_symbol() {
    local file=$1
    local symbol=$2
    local expected_type=$3
    local expected_value=$4
    local expected_size=$5
    local description=$6
    local record

    record=$(nm -P --defined-only "$file" | awk -v symbol="$symbol" '$1 == symbol { print $2, $3, $4 }')
    [[ "$record" == "$expected_type $expected_value $expected_size" ]] || \
        fail "$description symbol $symbol is ${record:-missing}, expected $expected_type $expected_value $expected_size"
}

for file in \
    "$launcher_source" "$main_source" "$interp_source" \
    "$launcher_elf" "$main_elf" "$interp_elf"; do
    require_regular_file "$file"
done

# These digests are the immutable retained-source origin gate.  Changing the
# catalog and source together must not silently redefine this evidence input.
assert_sha256 "$launcher_source" df014a4bc6d7f06cc9c46ef885fa007eddec024386b7a76bd87a8b5df2b30378 \
    'retained dynamic PIE launcher source'
assert_sha256 "$main_source" b93c70b964272cb7cf898965b9d28b0764270cfe97093d17581e80968fa7ab1d \
    'retained dynamic PIE main source'
assert_sha256 "$interp_source" 407dee2dca786758f185b8084060509c959c43f206cf9cfa37fbffdf1d63dd13 \
    'retained dynamic runtime interpreter source'

# These are produced by the digest-pinned OSDK image's clang 18 / GNU ld 2.42
# from fixed temporary filenames.  They make toolchain or link-layout drift a
# review event before the runtime starts accepting a different artifact.
assert_sha256 "$launcher_elf" 52b10cb5e9d2cf6161e54a5564cec8f1e550bcd1b8c1e51de46c499c060ef2a4 \
    'dynamic PIE launcher artifact'
assert_sha256 "$main_elf" d5ef13e058d54eb0f981ed2945af18ec496cc0522b7361d9aebac83b599541c7 \
    'dynamic PIE main artifact'
assert_sha256 "$interp_elf" aad628b14954a80210da3785c4fbd56f5187ac12843d1d5094e148ec83d08bf0 \
    'dynamic runtime interpreter artifact'

assert_header "$launcher_elf" EXEC 0x100001000 'launcher'
assert_header "$main_elf" DYN 0x12e0 'PIE main'
assert_header "$interp_elf" DYN 0x12d0 'runtime interpreter'

launcher_programs=$(readelf -lW "$launcher_elf")
main_programs=$(readelf -lW "$main_elf")
interp_programs=$(readelf -lW "$interp_elf")

assert_program_count "$launcher_programs" LOAD 3 'launcher'
assert_program_count "$launcher_programs" INTERP 0 'launcher'
assert_program_count "$launcher_programs" TLS 0 'launcher'
assert_program_count "$launcher_programs" DYNAMIC 0 'launcher'
assert_program_count "$main_programs" LOAD 4 'PIE main'
assert_program_count "$main_programs" INTERP 1 'PIE main'
assert_program_count "$main_programs" TLS 1 'PIE main'
assert_program_count "$main_programs" DYNAMIC 1 'PIE main'
assert_program_count "$interp_programs" LOAD 4 'runtime interpreter'
assert_program_count "$interp_programs" INTERP 0 'runtime interpreter'
assert_program_count "$interp_programs" TLS 1 'runtime interpreter'
assert_program_count "$interp_programs" DYNAMIC 1 'runtime interpreter'

grep -Fq '[Requesting program interpreter: /lib/ld-nexus-dynamic-runtime.so]' \
    <<<"$main_programs" || fail 'PIE main has the wrong PT_INTERP payload'

awk '$1 == "TLS" { ok = ($5 == "0x000004" && $6 == "0x000004" && $8 == "0x4") } END { exit !ok }' \
    <<<"$main_programs" || fail 'PIE main PT_TLS layout is not filesz=4 memsz=4 align=4'
awk '$1 == "TLS" { ok = ($5 == "0x000008" && $6 == "0x000010" && $8 == "0x8") } END { exit !ok }' \
    <<<"$interp_programs" || fail 'runtime interpreter PT_TLS layout is not filesz=8 memsz=16 align=8'

assert_no_wx_or_exec_stack "$launcher_programs" 'launcher'
assert_no_wx_or_exec_stack "$main_programs" 'PIE main'
assert_no_wx_or_exec_stack "$interp_programs" 'runtime interpreter'
assert_no_runtime_link_dependencies "$launcher_elf" 'launcher'
assert_no_runtime_link_dependencies "$main_elf" 'PIE main'
assert_no_runtime_link_dependencies "$interp_elf" 'runtime interpreter'

main_dynamic=$(readelf -dW "$main_elf")
interp_dynamic=$(readelf -dW "$interp_elf")
grep -Eq '\(FLAGS_1\).*PIE' <<<"$main_dynamic" || fail 'PIE main lacks DF_1_PIE'
grep -Fq '(SONAME)' <<<"$interp_dynamic" || fail 'runtime interpreter lacks DT_SONAME'
grep -Fq '[ld-nexus-dynamic-runtime.so]' <<<"$interp_dynamic" || \
    fail 'runtime interpreter has the wrong DT_SONAME'

assert_symbol "$launcher_elf" _start T 100001000 '' 'launcher'
assert_symbol "$main_elf" _start T 12e0 c 'PIE main'
assert_symbol "$main_elf" main_tls_value D 0 4 'PIE main'
assert_symbol "$interp_elf" _start T 12d0 c 'runtime interpreter'
assert_symbol "$interp_elf" interp_tls_init d 0 8 'runtime interpreter'
assert_symbol "$interp_elf" interp_tls_zero b 8 8 'runtime interpreter'

echo 'dynamic PIE artifact assertions: PASS retained_sources=3 artifacts=3 launcher=ET_EXEC main=ET_DYN interp=ET_DYN pt_interp=exact tls=main+interp runtime_dependencies=none'
