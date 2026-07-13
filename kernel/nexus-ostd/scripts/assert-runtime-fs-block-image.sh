#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly expected_elf_sha=0dc5ad40cb05e39592592ef3272ed45be4d71f9b147a534be20b9a5626c17bef
readonly expected_sector0_sha=4fb2b63ca7d483c6efaa756182133f05c7ef453fa82e94ce31826ebc4c104f66
readonly expected_image_sha=9357413ed9a96a23af1750cc304265dd7dd1835eb58eb1fb50119cd80d0bc8ca
readonly expected_elf_size=10232
readonly expected_image_size=10240
readonly sector_size=512

die() {
    echo "runtime fs block-image assertion: FAIL: $*" >&2
    exit 1
}

sha_file() {
    sha256sum "$1" | cut -d ' ' -f1
}

require_regular_file() {
    local label=$1
    local path=$2

    [[ -f "$path" && ! -L "$path" ]] ||
        die "$label is not a regular non-symlink file: $path"
}

if (( $# != 2 )); then
    die "usage: $0 RUNTIME_FS_ELF RAW_IMAGE"
fi

elf=$1
image=$2

for command_name in cmp cut head od sha256sum stat tail tr; do
    command -v "$command_name" >/dev/null 2>&1 || die "missing command: $command_name"
done

require_regular_file runtime-fs-elf "$elf"
require_regular_file raw-image "$image"

elf_size=$(stat -c %s "$elf")
image_size=$(stat -c %s "$image")
[[ $elf_size == "$expected_elf_size" ]] ||
    die "ELF size mismatch expected=$expected_elf_size actual=$elf_size"
[[ $image_size == "$expected_image_size" ]] ||
    die "raw image size mismatch expected=$expected_image_size actual=$image_size"
(( image_size % sector_size == 0 )) || die "raw image is not sector aligned"

elf_sha=$(sha_file "$elf")
image_sha=$(sha_file "$image")
sector0_sha=$(head -c "$sector_size" "$image" | sha256sum | cut -d ' ' -f1)
[[ $elf_sha == "$expected_elf_sha" ]] ||
    die "ELF SHA mismatch expected=$expected_elf_sha actual=$elf_sha"
[[ $sector0_sha == "$expected_sector0_sha" ]] ||
    die "sector 0 SHA mismatch expected=$expected_sector0_sha actual=$sector0_sha"
[[ $image_sha == "$expected_image_sha" ]] ||
    die "raw image SHA mismatch expected=$expected_image_sha actual=$image_sha"

cmp -n "$expected_elf_size" "$elf" "$image" >/dev/null ||
    die "raw image prefix differs from retained ELF"
padding_hex=$(tail -c "$((expected_image_size - expected_elf_size))" "$image" |
    od -An -v -tx1 | tr -d ' \n')
[[ $padding_hex == 0000000000000000 ]] ||
    die "raw image padding is not eight zero bytes"

echo "runtime fs block-image assertions: PASS elf_sha=$elf_sha sector0_sha=$sector0_sha image_sha=$image_sha elf_bytes=$elf_size image_bytes=$image_size sector_size=$sector_size prefix_exact=true zero_padded=true readonly_fixture=true"
