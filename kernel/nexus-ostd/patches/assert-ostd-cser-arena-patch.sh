#!/usr/bin/env bash
set -euo pipefail

expected_archive_sha=aa160b3c09e0471f85f76a069e327b3df0bc60d5191b2ce3a64cc15cd62038e1
expected_base_patch_sha=6167dc681e8f5e53c20e2ef2ccc40fc1924c722bb9ca37cc4ba4f70ba49b71db
expected_arena_patch_sha=a36a3c857f49640b0e4d5656e4171161b883337df46508ccbd349b3eca0975e0

script_dir=$(cd "$(dirname "$0")" && pwd)
repo_root=$(cd "$script_dir/../../.." && pwd)
archive=${NEXUS_OSTD_ARCHIVE:-/opt/nexus-source/ostd-0.18.0.crate}
arena_patch=${1:-"$script_dir/ostd-0.18.0-cser-arena.patch"}
patched=${2:-${NEXUS_OSTD_PATCHED_ROOT:-/opt/nexus-ostd/ostd-0.18.0}}
base_patch=${3:-"$repo_root/patches/ostd-0.18.0-cser.patch"}

fail() {
    echo "canonical OSTD CSER arena patch assertion failed: $*" >&2
    exit 1
}

for input in "$archive" "$base_patch" "$arena_patch"; do
    [[ -f $input && ! -L $input ]] || fail "input must be a non-symlink regular file: $input"
done
[[ -d $patched/src && ! -L $patched ]] || fail "missing patched OSTD tree: $patched"
find "$patched/src" -type l -print -quit | grep -q . \
    && fail "installed OSTD source tree contains a symlink"

echo "$expected_archive_sha  $archive" | sha256sum -c - >/dev/null \
    || fail "OSTD 0.18.0 archive hash mismatch"
echo "$expected_base_patch_sha  $base_patch" | sha256sum -c - >/dev/null \
    || fail "base OSTD CSER patch hash mismatch"
echo "$expected_arena_patch_sha  $arena_patch" | sha256sum -c - >/dev/null \
    || fail "OSTD CSER arena patch hash mismatch"

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/pristine" "$tmp/base" "$tmp/combined" "$tmp/reverse"
tar -xzf "$archive" -C "$tmp/pristine" --strip-components=1
cp -a "$tmp/pristine/." "$tmp/base/"
cp -a "$tmp/pristine/." "$tmp/combined/"

if patch --fuzz=0 --batch --dry-run --forward -d "$tmp/pristine" -p1 \
    < "$arena_patch" >/dev/null 2>&1; then
    fail "arena patch is not ordered after the base CSER overlay"
fi

patch --fuzz=0 --batch --forward -d "$tmp/base" -p1 \
    < "$base_patch" >/dev/null \
    || fail "base CSER overlay does not apply to pinned OSTD"
patch --fuzz=0 --batch --dry-run --forward -d "$tmp/base" -p1 \
    < "$arena_patch" >/dev/null \
    || fail "arena overlay does not apply after the base CSER overlay"

patch --fuzz=0 --batch --forward -d "$tmp/combined" -p1 \
    < "$base_patch" >/dev/null
patch --fuzz=0 --batch --forward -d "$tmp/combined" -p1 \
    < "$arena_patch" >/dev/null
patch --fuzz=0 --batch --dry-run --reverse -d "$tmp/combined" -p1 \
    < "$arena_patch" >/dev/null \
    || fail "fresh combined tree does not reverse the arena overlay cleanly"

diff -ru "$tmp/combined/src" "$patched/src" >/dev/null \
    || fail "installed OSTD source differs from the two pinned overlays"

cp -a "$tmp/combined/." "$tmp/reverse/"
patch --fuzz=0 --batch --reverse -d "$tmp/reverse" -p1 \
    < "$arena_patch" >/dev/null
patch --fuzz=0 --batch --dry-run --reverse -d "$tmp/reverse" -p1 \
    < "$base_patch" >/dev/null \
    || fail "base overlay cannot reverse after removing the arena overlay"

coherent=$patched/src/mm/dma/dma_coherent.rs
dma_mod=$patched/src/mm/dma/mod.rs
dma_util=$patched/src/mm/dma/util.rs

for source in "$coherent" "$dma_mod" "$dma_util"; do
    [[ -f $source && ! -L $source ]] || fail "missing exact-DMA source: $source"
done

awk '
    $0 == "pub struct ExactDmaMapError {" { errors++ }
    $0 == "    segment: Segment<()>," { segment_fields++ }
    $0 == "    pub fn into_segment(self) -> Segment<()> {" { segment_returns++ }
    $0 == "    pub fn into_parts(self) -> (ExactDmaMapFailure, Segment<()>) {" { part_returns++ }
    $0 == "    pub fn from_segment_at(" { constructors++; in_constructor = 1 }
    in_constructor && $0 == "        segment: Segment<()>," { constructor_segments++ }
    in_constructor && $0 == "        exact_daddr: Daddr," { constructor_daddrs++ }
    in_constructor && /cvm_need_private_protection\(\)/ { cvm_checks++; cvm_line = NR }
    in_constructor && /prepare_dma_at\(&paddr_range, exact_daddr\)/ {
        exact_prepares++
        prepare_line = NR
    }
    in_constructor && $0 == "                return Err(ExactDmaMapError { segment, failure });" {
        owned_errors++
        error_line = NR
    }
    in_constructor && $0 == "            map_daddr: Some(map_daddr)," {
        exact_owners++
        owner_line = NR
    }
    in_constructor && $0 == "            is_cache_coherent: true," { coherent_only++ }
    in_constructor && $0 == "    }" && exact_owners == 1 { in_constructor = 0 }
    END {
        if (errors != 1 || segment_fields != 1 || segment_returns != 1 ||
            part_returns != 1 || constructors != 1 || constructor_segments != 1 ||
            constructor_daddrs != 1 || cvm_checks != 1 || exact_prepares != 1 ||
            owned_errors != 1 || exact_owners != 1 || coherent_only != 1 ||
            in_constructor)
            exit 1
        exit !(cvm_line < prepare_line && prepare_line < error_line &&
               error_line < owner_line)
    }
' "$coherent" || fail "caller-owned exact DmaCoherent contract is incomplete"

awk '
    $0 == "pub(super) unsafe fn prepare_dma_at(" { functions++; in_exact = 1 }
    in_exact && /if !has_dma_remapping\(\)/ { remap_checks++; remap_line = NR }
    in_exact && /if !exact_daddr\.is_multiple_of\(PAGE_SIZE\)/ {
        alignment_checks++
        alignment_line = NR
    }
    in_exact && /exact_daddr\.checked_add\(pa_range\.len\(\)\)/ {
        overflow_checks++
        overflow_line = NR
    }
    in_exact && /\.alloc_specific\(&daddr_range\)/ {
        specific_allocs++
        alloc_line = NR
    }
    in_exact && /alloc_unprotect_physical_range\(pa_range\)/ {
        pfn_tracks++
        pfn_line = NR
    }
    in_exact && /iommu::map\(map_daddr, map_paddr\)/ {
        pte_maps++
        map_line = NR
    }
    in_exact && /\.free\(/ { premature_frees++ }
    in_exact && $0 == "    Ok(exact_daddr)" { exact_returns++; return_line = NR }
    $0 == "/// Unprepares a physical address range from DMA mapping." { in_exact = 0 }
    END {
        if (functions != 1 || remap_checks != 1 || alignment_checks != 1 ||
            overflow_checks != 1 || specific_allocs != 1 || pfn_tracks != 1 ||
            pte_maps != 1 || premature_frees != 0 || exact_returns != 1 ||
            in_exact)
            exit 1
        exit !(remap_line < alignment_line && alignment_line < overflow_line &&
               overflow_line < alloc_line && alloc_line < pfn_line &&
               pfn_line < map_line && map_line < return_line)
    }
' "$dma_util" || fail "exact IOVA reservation ordering is incomplete"

[[ $(grep -Fc 'allocator::daddr_allocator(&irq_guard).free(daddr_range);' "$dma_util") == 1 ]] \
    || fail "exact IOVA must have one allocator release site"
[[ $(grep -Fc 'PollDmaUnmap::Complete => Ok(self.finish()),' "$coherent") == 1 ]] \
    || fail "IOTLB completion must uniquely reach DMA finish"
[[ $(grep -Fc 'unsafe { complete_unprepare_dma(&paddr_range, daddr_range) };' "$coherent") == 1 ]] \
    || fail "DMA finish must uniquely release retained ownership"
grep -Fq 'ExactDmaMapError, ExactDmaMapFailure' "$dma_mod" \
    || fail "exact DMA error API is not exported"

echo "canonical OSTD CSER arena patch: PASS archive=pinned base_patch=hash-bound arena_patch=hash-bound order=base+arena apply=true reverse=true source=exact coherent_segment=returned-on-error exact_iova=alloc_specific no_iova_or_pte_on-reported-failure=true reuse_after=iotlb-complete-only"
