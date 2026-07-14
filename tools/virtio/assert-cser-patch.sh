#!/usr/bin/env bash
set -euo pipefail

readonly expected_archive_sha=cfdc1c628cdd8ce7c3b9e65a8ed550d0338e9ef9f911e729666f1cce097de2f7
readonly expected_patch_sha=7576d6810af8ff4a2d4cbcd0dc02373946031aa2e3f7ae0528b0127b5ea33762
readonly expected_upstream_license_sha=bf2a1b2f68528d6cb47939394b181236858d3e9c6c5e43b3af0650976567f152
# The repository copy preserves the upstream text and adds one conventional
# final newline; the exact no-final-newline archive member is checked above.
readonly expected_notice_sha=3ec2e9caabb8850bc49cb454352ef709f197024811cb3f749239b47abd439af4
archive=${NEXUS_VIRTIO_ARCHIVE:-/opt/nexus-source/virtio-drivers-0.13.0.crate}
patched=${2:-${NEXUS_VIRTIO_PATCHED_ROOT:-/opt/nexus-virtio/virtio-drivers-0.13.0}}

if [[ $# -ge 1 ]]; then
    patch_file=$1
elif [[ -f /repo/patches/virtio-drivers-0.13.0-cser.patch ]]; then
    patch_file=/repo/patches/virtio-drivers-0.13.0-cser.patch
else
    script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
    patch_file=$(cd -- "$script_dir/../.." && pwd)/patches/virtio-drivers-0.13.0-cser.patch
fi
license_file=${3:-$(dirname -- "$patch_file")/virtio-drivers-0.13.0-LICENSE-MIT}

fail() {
    echo "canonical virtio-drivers CSER patch assertion failed: $*" >&2
    exit 1
}

section() {
    local start=$1
    local end=$2
    local source=$3
    sed -n "/$start/,/$end/p" "$source"
}

declaration_prefix() {
    local declaration=$1
    local source=$2
    awk -v declaration="$declaration" '
        $0 ~ declaration {
            start = NR - 1
            while (start > 0 && lines[start] !~ /^[[:space:]]*$/) start--
            for (line = start + 1; line < NR; line++) print lines[line]
            print
            found = 1
            exit
        }
        { lines[NR] = $0 }
        END { if (!found) exit 1 }
    ' "$source"
}

has_manual_clone_or_copy() {
    local type=$1
    local source=$2
    awk -v type="$type" '
        /^[[:space:]]*impl([[:space:]<]|$)/ {
            signature = $0
            while (signature !~ /\{/ && (getline next_line) > 0) {
                signature = signature " " next_line
            }
            if (signature ~ /(Clone|Copy)/ && signature ~ /for[[:space:]]*/ && signature ~ type) {
                found = 1
            }
        }
        END { exit found ? 0 : 1 }
    ' "$source"
}

[[ -f $archive && ! -L $archive ]] || fail "missing regular upstream archive: $archive"
[[ -f $patch_file && ! -L $patch_file ]] || fail "missing regular canonical patch: $patch_file"
[[ -f $license_file && ! -L $license_file ]] \
    || fail "missing regular upstream MIT license notice: $license_file"
[[ -d $patched/src ]] || fail "missing patched virtio-drivers tree: $patched"
echo "$expected_archive_sha  $archive" | sha256sum -c - >/dev/null \
    || fail 'upstream virtio-drivers archive digest mismatch'
echo "$expected_patch_sha  $patch_file" | sha256sum -c - >/dev/null \
    || fail 'canonical virtio-drivers patch digest mismatch'
echo "$expected_notice_sha  $license_file" | sha256sum -c - >/dev/null \
    || fail 'repository MIT license notice digest mismatch'

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar -xzf "$archive" -C "$tmp"
pristine=$tmp/virtio-drivers-0.13.0
echo "$expected_upstream_license_sha  $pristine/LICENSE" | sha256sum -c - >/dev/null \
    || fail 'upstream archive MIT license digest mismatch'
if ! cmp -s "$license_file" <(sed -e '$a\' "$pristine/LICENSE"); then
    fail 'repository MIT license notice differs from upstream text'
fi
patch --batch --forward -d "$pristine" -p1 <"$patch_file" >/dev/null \
    || fail 'canonical patch does not apply to the pinned archive'
patch --batch --dry-run --reverse -d "$pristine" -p1 <"$patch_file" >/dev/null \
    || fail 'freshly patched tree does not reverse cleanly'
patch --batch --dry-run --reverse -d "$patched" -p1 <"$patch_file" >/dev/null \
    || fail 'installed patched tree does not reverse cleanly'
diff -ru "$pristine/src" "$patched/src" >/dev/null \
    || fail 'installed source differs from canonical patch output'

queue=$patched/src/queue.rs
prepared=$(section '^pub struct PreparedVirtQueue' '^}' "$queue")
prepared_prefix=$(declaration_prefix '^pub struct PreparedVirtQueue' "$queue") \
    || fail 'cannot isolate linear prepared-token declaration prefix'
grep -Fq 'queue: ManuallyDrop<VirtQueue<H, SIZE>>,' <<<"$prepared" \
    || fail 'linear prepared token does not retain its queue with ManuallyDrop'
if grep -Eq '#\[derive\([^]]*(Clone|Copy)' <<<"$prepared_prefix"; then
    fail 'linear prepared token became Clone or Copy'
fi
if has_manual_clone_or_copy PreparedVirtQueue "$queue"; then
    fail 'linear prepared token gained a handwritten Clone or Copy implementation'
fi
if grep -Fq 'pub fn new(' <<<"$prepared"; then
    fail 'callers can construct a prepared token without queue preparation'
fi

drop_block=$(section '^impl<H: Hal, const SIZE: usize> Drop for PreparedVirtQueue' '^}' "$queue")
grep -Fq 'Fail closed: an unresolved prepared chain retains its queue DMA' <<<"$drop_block" \
    || fail 'unresolved prepared token no longer fails closed'
if grep -Eq '(ManuallyDrop::take|drop\((self\.)?queue|into_inner)' <<<"$drop_block"; then
    fail 'PreparedVirtQueue Drop releases an unresolved queue owner'
fi

prepare=$(section '^    pub unsafe fn prepare_add' '^    }' "$queue")
grep -Fq 'self.prepare_add_in_place(inputs, outputs)' <<<"$prepare" \
    || fail 'public prepare path does not use the audited in-place preparation'
grep -Fq 'queue: ManuallyDrop::new(self)' <<<"$prepare" \
    || fail 'successful prepare does not transfer the exact queue linearly'

prepare_inner=$(section '^    unsafe fn prepare_add_in_place' '^    }' "$queue")
grep -Fq 'self.add_direct(inputs, outputs)' <<<"$prepare_inner" \
    || fail 'prepare path no longer initializes direct descriptors and DMA shares'
grep -Fq '(*self.avail.as_ptr()).ring[avail_slot as usize] = head;' <<<"$prepare_inner" \
    || fail 'prepare path no longer initializes the available-ring slot'
if grep -Eq '(\.idx|publish_prepared|Ordering::Release)' <<<"$prepare_inner"; then
    fail 'prepare path publishes the available index'
fi

publish=$(section '^    pub fn publish_prepared' '^    }' "$queue")
grep -Fq 'pub fn publish_prepared(self) -> (VirtQueue<H, SIZE>, u16)' <<<"$publish" \
    || fail 'publish is not a linear infallible token consumption'
grep -Fq 'ManuallyDrop::take(&mut this.queue)' <<<"$publish" \
    || fail 'publish does not consume the exact retained queue'
grep -Fq 'queue.publish_prepared_in_place();' <<<"$publish" \
    || fail 'publish bypasses the unique release-store helper'
if grep -Eq '(Result<|\?|Vec|Box|collect|push|insert)' <<<"$publish"; then
    fail 'publish regained a fallible or allocating operation'
fi

publish_inner=$(section '^    fn publish_prepared_in_place' '^    }' "$queue")
fence_line=$(grep -nF 'fence(Ordering::SeqCst);' <<<"$publish_inner" | cut -d: -f1)
store_line=$(grep -nF '.store(self.avail_idx, Ordering::Release);' <<<"$publish_inner" | cut -d: -f1)
[[ -n $fence_line && -n $store_line && $fence_line -lt $store_line ]] \
    || fail 'publish lost fence-before-Release ordering'
[[ $(grep -Fc '.store(self.avail_idx, Ordering::Release);' "$queue") == 1 ]] \
    || fail 'available-index Release store is not unique'
if grep -Eq '(Result<|\?|Vec|Box|collect|push|insert)' <<<"$publish_inner"; then
    fail 'release-store helper regained a fallible or allocating operation'
fi

cancel=$(section '^    pub unsafe fn cancel_prepared' '^    }' "$queue")
grep -Fq 'ManuallyDrop::take(&mut this.queue)' <<<"$cancel" \
    || fail 'cancel does not consume the exact retained queue'
grep -Fq 'cancel_prepared_in_place(this.head, inputs, outputs)' <<<"$cancel" \
    || fail 'cancel does not carry the prepared token and exact buffers'
cancel_inner=$(section '^    unsafe fn cancel_prepared_in_place' '^    }' "$queue")
grep -Fq '(*self.avail.as_ptr()).ring[avail_slot as usize] = 0;' <<<"$cancel_inner" \
    || fail 'cancel leaves stale unpublished available-ring metadata'
grep -Fq 'self.recycle_descriptors(head, inputs, outputs);' <<<"$cancel_inner" \
    || fail 'cancel does not recycle descriptors and unshare exact buffers'
if grep -Fq '.idx' <<<"$cancel_inner"; then
    fail 'cancel mutates a device-visible queue index'
fi

add=$(section '^    pub unsafe fn add' '^    }' "$queue")
grep -Fq 'self.prepare_add_in_place(inputs, outputs)' <<<"$add" \
    || fail 'legacy add no longer reuses split preparation'
grep -Fq 'self.publish_prepared_in_place();' <<<"$add" \
    || fail 'legacy add no longer reuses split publication'
for test_name in \
    'fn prepare_is_invisible_until_publish()' \
    'fn cancel_prepared_restores_queue_without_publication()'; do
    grep -Fq "$test_name" "$queue" || fail "missing upstream regression test: $test_name"
done
for validation_evidence in \
    'Error::InvalidParam' \
    'Error::QueueFull' \
    'let before = validation_snapshot(&queue);' \
    'let queue = error.into_queue();' \
    'assert_eq!(validation_snapshot(&queue), before);' \
    'VALIDATION_SHARE_CALLS.load(Ordering::SeqCst)' \
    'VALIDATION_UNSHARE_CALLS.load(Ordering::SeqCst)'; do
    grep -Fq "$validation_evidence" "$queue" \
        || fail "validation rollback tests lack evidence: $validation_evidence"
done

echo 'canonical virtio-drivers CSER patch: PASS archive=pinned license=MIT+pinned patch=hash-bound apply=true reverse=true prepared_token=linear+fail-closed+non-clone prepare=descriptor+dma+avail-slot+validation-atomic publish=unique-infallible-release cancel=recycle+unshare legacy_add=split-compatible'
