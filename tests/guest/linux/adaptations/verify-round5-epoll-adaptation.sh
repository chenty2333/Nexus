#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

readonly expected_source_sha=21d322d582465c939367977e6b7f23474ccedebacfa6d5f27ec97d979a9bb13c
readonly expected_patch_sha=cf19e05067a79fec35f0a5ed57e5f302129707a7b0dd57affc93bed56903026b
readonly expected_adapted_source_sha=1aad9899aceb23cd2e21c067a96bffed92543fa7bbd92e91f4d807a0e4843205

die() {
    echo "round5 epoll adaptation oracle: FAIL: $*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

sha256_file() {
    sha256sum "$1" | cut -d ' ' -f1
}

check_sha() {
    local label=$1
    local path=$2
    local expected=$3
    local actual

    actual=$(sha256_file "$path")
    [[ "$actual" == "$expected" ]] ||
        die "$label SHA-256 mismatch: expected=$expected actual=$actual path=$path"
}

if [[ $# -ne 0 ]]; then
    die "usage: $0"
fi

for command_name in awk clang cp cut dirname grep mktemp patch readelf rm sha256sum strings; do
    require_command "$command_name"
done

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd -- "$script_dir/../../../.." && pwd)
source_file=${NEXUS_ROUND5_EPOLL_SOURCE:-$repo_root/tests/guest/linux/sources/linux-round5-epoll-smoke/round5_epoll_smoke.S}
patch_file=${NEXUS_ROUND5_EPOLL_PATCH:-$script_dir/round5-epoll-linux-regular-file.patch}

[[ -f "$source_file" ]] || die "missing retained source: $source_file"
[[ -f "$patch_file" ]] || die "missing adaptation patch: $patch_file"
check_sha "retained source" "$source_file" "$expected_source_sha"
check_sha "adaptation patch" "$patch_file" "$expected_patch_sha"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

adapted_source="$tmp/round5_epoll_smoke.S"
object_file="$tmp/round5_epoll_smoke.o"
elf_file="$tmp/round5_epoll_smoke.elf"
host_oracle="$tmp/regular-file-epoll-oracle"

cp -- "$source_file" "$adapted_source"
(
    cd -- "$tmp"
    patch \
        --batch \
        --forward \
        --fuzz=0 \
        --no-backup-if-mismatch \
        --reject-file=- \
        --silent \
        -p1 \
        <"$patch_file"
)
check_sha "adapted source" "$adapted_source" "$expected_adapted_source_sha"

clang \
    --target=x86_64-unknown-linux-gnu \
    -c \
    "$adapted_source" \
    -o "$object_file"
clang \
    --target=x86_64-unknown-linux-gnu \
    -nostdlib \
    -static \
    -Wl,--build-id=none \
    -Wl,-z,noexecstack \
    -Wl,-z,max-page-size=4096 \
    "$object_file" \
    -o "$elf_file"

header=$(readelf -hW "$elf_file")
programs=$(readelf -lW "$elf_file")
for pattern in \
    'Class:.*ELF64' \
    'Data:.*little endian' \
    'Type:.*EXEC' \
    'Machine:.*X86-64'; do
    grep -Eq "$pattern" <<<"$header" || die "ELF header assertion failed: $pattern"
done
if grep -Eq '^[[:space:]]*(INTERP|DYNAMIC)[[:space:]]' <<<"$programs"; then
    die "adapted artifact must remain a static executable"
fi
if [[ $(grep -Ec '^[[:space:]]*LOAD[[:space:]]' <<<"$programs") -lt 1 ]]; then
    die "adapted artifact must contain at least one PT_LOAD"
fi
if awk '
    $1 == "LOAD" {
        flags = ""
        for (field = 7; field < NF; field++) {
            flags = flags $field
        }
        if (flags ~ /W/ && flags ~ /E/) {
            writable_executable = 1
        }
    }
    END { exit writable_executable ? 0 : 1 }
' <<<"$programs"; then
    die "adapted artifact contains a writable executable PT_LOAD"
fi
strings -a "$elf_file" | grep -Fxq '/bin/linux-hello' ||
    die "adapted artifact lost the fixed retained artifact lookup"
strings -a "$elf_file" | grep -Fxq 'round5 epoll ok' ||
    die "adapted artifact lost its retained success marker"

# Linux does not accept regular files in an epoll interest list.  The retained
# program encoded the opposite legacy assumption, so independently pin the
# host-kernel result that justifies the visible source adaptation.  The full
# adapted workload still runs only in the Nexus guest, where /bin/linux-hello
# is a bounded artifact lookup.
clang -O2 -Wall -Wextra -Werror -x c -o "$host_oracle" - <<'EOF'
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 1) return 10;
    int fd = open(argv[0], O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 11;
    int epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) return 12;
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = UINT64_C(0x44)};
    errno = 0;
    int result = epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
    int saved_errno = errno;
    close(epfd);
    close(fd);
    return result == -1 && saved_errno == EPERM ? 0 : 13;
}
EOF
"$host_oracle" || die "host Linux did not reject a regular file with EPERM"

artifact_sha=$(sha256_file "$elf_file")
echo "round5 epoll adaptation oracle: PASS source_sha=$expected_source_sha patch_sha=$expected_patch_sha adapted_source_sha=$expected_adapted_source_sha artifact_sha=$artifact_sha regular_file_epoll=EPERM full_host_run=false qemu_required=true"
