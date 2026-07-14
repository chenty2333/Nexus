# Nexus v0.1.0 artifact and reproducibility guide

This guide defines the reproducibility contract for the Nexus CSER research
prototype. The source release is identified by the annotated `v0.1.0` tag,
which release policy and tag protection treat as immutable; the exact commit and
source fingerprint for any evidence run are recorded inside that run's
manifest. The reference release bundle is an integrity-preserving record of one accepted run.
A new full run produces a new nonce, timestamps, performance observations, and
hashes, so reproducibility does not mean that two runs are byte-identical.

The archive of record for this release is
[Zenodo record 21343496](https://zenodo.org/records/21343496), with version DOI
[10.5281/zenodo.21343496](https://doi.org/10.5281/zenodo.21343496). It contains
the evidence bundle, the exact tagged source archive, and one SHA-256 sidecar
for each:

| Archived file | SHA-256 |
| --- | --- |
| `nexus-artifact-bundle-v0.1.0.zip` | `470363102f95fdc6f98ca02c29623f6d2bca58b1a118eab7b74993a0666deef1` |
| `nexus-source-v0.1.0.zip` | `21fa31d5f31adcdf9516535ce9df13ced3e9b4e403b09b5189d3914f6fabd046` |

The corresponding protected Git tag and
[GitHub Release](https://github.com/chenty2333/Nexus/releases/tag/v0.1.0)
remain the source-history anchors. The DOI was added to later `main` metadata;
the already published `v0.1.0` tag was not moved or rewritten.

## Post-v0.1 current-main verifier successor

The counts and procedures below remain the frozen `v0.1.0` contract. Current
main is developing a separate `nexus.verification.v6` successor after the
upstream mutable prerelease URL replaced its same-named TLA+ asset. It vendors
the exact JAR bytes used by the accepted run, checks the installed JAR before
the formal commands, requires exact TLC and PlusCal version lines in every
model/spec log, and seals a same-container formal-verifier receipt between the
start and model/spec receipts.

The current-main v6 population is 12 specifications, 17 research stages, and
52 generated evidence artifacts. Four static verifier files and five control
records bring the complete bundle to 61 `SHA256SUMS` payload entries and 62
regular files including the checksum index. These are acceptance-contract
figures for the unreleased successor, not a relabeling of the published v0.1
bundle. Current main must still pass a clean cold run and exact-SHA CI before
those figures describe an accepted checkpoint.

## What the artifact supports

The complete gate covers the safe-Rust reference model, twelve PlusCal/TLA+
families, the bounded OSTD kernel and mediated VirtIO QEMU receipts, filesystem,
network, predecessor and Linux I/O composition oracles, and the Stage 7B
concurrency, fault, scale, performance, prior-art, and contribution decision.

The accepted boundary remains deliberately narrow:

- bounded graph and single CPU;
- `production transition source under a Loom-modeled outer mutex` for the 14
  concurrency races;
- 20 Checked fault cells, 14 Checked structural scale points, and 29 Observed
  guest-visible TSC cases with no thresholds;
- a 16-row primary-source comparison and `narrow` contribution verdict;
- component consistency, not same-boot or identity-preserving Stage 5B
  composition;
- no SMP, hardware-cycle, lock-freedom, durable-external-effect, Linux-breadth,
  full-production-adapter-equivalence, novelty, firstness, or proof claim.

## Host and resource envelope

The supported host is Linux x86-64 with a working Docker daemon, Bash, Git,
`awk`, coreutils, `grep`, `sed`, and `flock`. The workflow uses `linux/amd64`
containers. QEMU is fixed to Q35, an `Icelake-Server,+x2apic` CPU model, 1 GiB
guest memory, one vCPU, and single-thread TCG; KVM and physical devices are not
required.

Reserve roughly 90 minutes and 20 GB of free Docker/workspace storage for a
cold full run. These are planning figures, not performance promises. The
accepted local cold run took about 10 minutes on its original host, while the
accepted GitHub full job took about 48 minutes. The three active images report
approximately 1.87 GB, 6.33 GB, and 6.30 GB, and generated targets can add about
12 GB before Docker layer sharing and cache policy are considered.

Image construction requires network access to the pinned container bases,
Rust components, crate archives, Debian packages, and the TLA+ jar. Once the
images have been built, verification containers run with `--network none` and
Cargo runs offline. This is an offline-runtime contract, not a claim that a
first build remains possible forever without archived dependencies.

## Clean-clone full reproduction

```bash
git clone https://github.com/chenty2333/Nexus.git
cd Nexus
git checkout --detach v0.1.0
git status --short
./x doctor
./x test --quick
NEXUS_REBUILD=1 ./x verify
./x verify-bundle target/verification/artifact-bundle
```

`git status --short` must initially print nothing. The cold `./x verify` form is
the canonical release gate; `./x test --full` traverses the same execution graph
but is not a release-sealing invocation. The canonical command regenerates all
evidence, seals the receipt chain and manifest, creates the complete bundle, and
verifies that bundle before returning success. Focused commands are diagnostics
and cannot publish a successful manifest or bundle.

The generated manifest records the exact Git revision, all tracked and
nonignored-untracked source bytes and modes, dirty state, invocation,
`NEXUS_REBUILD`, per-run nonce, orchestration-token hash, research boundaries,
specification and stage populations, and all 46 artifact byte counts and
SHA-256 values.

## Reference-bundle verification

The release asset is named `nexus-artifact-bundle-v0.1.0.zip`. Extract its
contents into `target/verification/artifact-bundle/` in a `v0.1.0` checkout,
then run:

```bash
./x verify-bundle target/verification/artifact-bundle
```

This path does not build the model or kernels, run TLA+, regenerate evidence, or
start QEMU. It runs the Rust bundle verifier in the pinned root tooling
container; a host without that container may need network access once to build
the tooling image. The command recomputes the current checkout's revision,
nonignored-source fingerprint, and dirty state, and accepts only a matching clean
checkout plus a canonical cold `NEXUS_REBUILD=1 ./x verify` manifest.

The verifier rejects:

- a missing, duplicate, additional, nonregular, or symlinked file;
- a noncanonical or inconsistent `SHA256SUMS`;
- any artifact whose bytes or SHA-256 differ from the manifest;
- revision, source, nonce, token-hash, invocation, dirty-state, or rebuild drift
  among the start, model/spec, completion, and manifest records;
- a model/spec receipt whose SHA-256 is not the completion prerequisite;
- a completion receipt whose SHA-256 is not
  `manifest.completion_receipt_sha256`;
- any drift from 12 specifications, 15 stages, 46 artifacts, or the frozen
  research-boundary object.

`SHA256SUMS` establishes self-consistency inside the extracted directory. The
recorded annotated-tag object ID, exact-SHA CI run, release asset SHA-256, and
tag-protection/release policy are the external trust anchors. A normal Git tag
is technically movable, and this checker does not claim cryptographic author
identity.

## Bundle layout

The directory contains exactly 51 regular files:

```text
SHA256SUMS
target/verification/manifest.json
target/verification/.stage7a-verify-start.json
target/verification/.stage7a-model-spec-complete.json
target/verification/.stage7a-verify-complete.json
target/verification/*-pluscal.log                  (12)
target/verification/*-tlc.log                      (12)
target/verification/*-oracle.log and stage7b/*
kernel/nexus-ostd/artifacts/*
experiments/ostd-virtio-cser-spike/artifacts/*
```

The manifest's 46 artifacts plus the four manifest/control records are the 50
payload entries covered by `SHA256SUMS`; `SHA256SUMS` does not list itself. The
bundle preserves repository-relative paths so every manifest path resolves
without a translation table.

## Success criteria

Reference-bundle integrity succeeds only when all 51 files and the complete
receipt/hash chain match that published run exactly.

A fresh computational reproduction succeeds when its new bundle verifier
passes and it retains the same contract populations and boundaries: 12
specifications, 15 stages, 46 artifacts, 14 races, 20 fault cells, 14 scale
points, 29 performance cases, 16 prior-art rows, and a `narrow` verdict.
Different nonce, timestamps, raw TSC samples, and resulting artifact hashes are
expected. Raw performance values have no cross-machine threshold and must not
be compared as hardware-cycle results.

The final acceptance record additionally requires a clean cold local run and a
successful GitHub Actions full job at the exact released commit. GitHub Actions
artifacts are short-lived transport, not the archive of record. The release
source, complete bundle, asset SHA-256, and citation metadata should be retained
in a DOI-bearing long-term archive. For `v0.1.0`, the Zenodo record and version
DOI named above satisfy that archival step.

## Maintainer sealing procedure for future releases

The `v0.1.0` procedure is complete and must not be rerun against that tag. The
following is a template for a new, unreleased version. First update and validate
the version/date in `CITATION.cff` and `.zenodo.json`, then commit every
implementation, narrative, release-tooling, and metadata change. The procedure
requires authenticated `gh`, plus `jq`, `unzip`, `curl`, and `sha256sum`. It
keeps downloaded material below ignored `target/`, so the public bundle
verifier can require an otherwise clean checkout. Run all blocks in the same
Bash process so their derived identifiers remain bound across steps.

First produce the local cold receipt, push the exact commit, and select only a
successful push workflow at that SHA:

```bash
set -euo pipefail

repo=chenty2333/Nexus
version=${VERSION:?set VERSION to a new release tag such as v0.2.0}
test "$version" != v0.1.0
test "${version#v}" != "$version"
test "$(jq -r .version .zenodo.json)" = "${version#v}"
manifest_schema=${MANIFEST_SCHEMA:?set the schema frozen by the new release contract}
expected_specifications=${EXPECTED_SPECIFICATIONS:?set the frozen specification count}
expected_stages=${EXPECTED_STAGES:?set the frozen stage/evidence-family count}
expected_artifacts=${EXPECTED_ARTIFACTS:?set the frozen manifest artifact count}
asset="nexus-artifact-bundle-$version.zip"
release_dir="target/release/$version"
release_sha=$(git rev-parse HEAD)

test -z "$(git status --porcelain=v1 --untracked-files=all)"
test -z "$(git tag --list "$version")"
NEXUS_REBUILD=1 ./x verify
./x verify-bundle target/verification/artifact-bundle
test -z "$(git status --porcelain=v1 --untracked-files=all)"

git push origin "$release_sha":refs/heads/main
run_id=
for _ in $(seq 1 60); do
  listed=$(gh run list --repo "$repo" --workflow ci.yml --event push \
    --commit "$release_sha" --limit 20 \
    --json databaseId,headSha,createdAt)
  run_id=$(jq -r --arg sha "$release_sha" '
    [.[] | select(.headSha == $sha)]
    | sort_by(.createdAt) | last | .databaseId // empty
  ' <<<"$listed")
  [[ -n $run_id ]] && break
  sleep 5
done
test -n "$run_id"
gh run watch "$run_id" --repo "$repo" --exit-status
run=$(gh api "repos/$repo/actions/runs/$run_id")
test "$(jq -r .head_sha <<<"$run")" = "$release_sha"
test "$(jq -r .status <<<"$run")" = completed
test "$(jq -r .conclusion <<<"$run")" = success
run_attempt=$(jq -r .run_attempt <<<"$run")

jobs=$(gh api "repos/$repo/actions/runs/$run_id/jobs?filter=latest")
jq -e '
  [.jobs[] | select(.name == "quick feedback" or .name == "full system verification")] as $required
  | ($required | length) == 2
    and ($required | all(.conclusion == "success"))
' <<<"$jobs" >/dev/null
```

Download the raw Actions ZIP rather than using `gh run download`, which extracts
it. Bind its API digest to the bytes, extract a fresh copy, and run the strict
checkout-bound verifier:

```bash
artifact_name="nexus-verification-bundle-$run_attempt"
artifacts=$(gh api "repos/$repo/actions/runs/$run_id/artifacts")
artifact_id=$(jq -er --arg name "$artifact_name" --arg sha "$release_sha" '
  [.artifacts[]
   | select(.name == $name and (.expired | not) and .workflow_run.head_sha == $sha)]
  | if length == 1 then .[0].id else error("expected one exact-SHA bundle") end
' <<<"$artifacts")
api_digest=$(jq -er --arg name "$artifact_name" '
  [.artifacts[] | select(.name == $name)][0].digest | ltrimstr("sha256:")
' <<<"$artifacts")

rm -rf "$release_dir" target/verification/artifact-bundle
mkdir -p "$release_dir" target/verification/artifact-bundle
zip_path="$release_dir/$asset"
gh api "repos/$repo/actions/artifacts/$artifact_id/zip" >"$zip_path"
outer_sha256=$(sha256sum "$zip_path" | cut -d ' ' -f1)
test "$outer_sha256" = "$api_digest"
printf '%s  %s\n' "$outer_sha256" "$asset" \
  >"$release_dir/$asset.sha256"

unzip -q "$zip_path" -d target/verification/artifact-bundle
./x verify-bundle target/verification/artifact-bundle
manifest=target/verification/artifact-bundle/target/verification/manifest.json
jq -e --arg sha "$release_sha" --arg schema "$manifest_schema" \
  --argjson specifications "$expected_specifications" \
  --argjson stages "$expected_stages" \
  --argjson artifacts "$expected_artifacts" '
  .schema == $schema
  and .status == "passed"
  and .revision == $sha
  and .worktree_dirty == false
  and .rebuild_requested == true
  and .nexus_rebuild == "1"
  and (.specifications | length) == $specifications
  and (.stages | length) == $stages
  and (.artifacts | length) == $artifacts
' "$manifest" >/dev/null
```

Only after that audit, create and record the annotated tag object, push it, and
publish the two GitHub Release assets. The procedure creates an active,
no-bypass ruleset that blocks updates and deletion of exactly `$version`; even
with that protection, never force-move or recreate a released tag.

```bash
git tag -a "$version" "$release_sha" \
  -m "Nexus $version: CSER research artifact"
tag_object=$(git rev-parse "$version^{tag}")
test "$(git rev-list -n 1 "$version")" = "$release_sha"
git push origin "refs/tags/$version"
test "$(git ls-remote origin "refs/tags/$version^{}" | cut -f1)" = "$release_sha"

ruleset=$(gh api --method POST "repos/$repo/rulesets" --input - <<JSON
{
  "name": "Protect Nexus $version release tag",
  "target": "tag",
  "enforcement": "active",
  "bypass_actors": [],
  "conditions": {
    "ref_name": {
      "include": ["refs/tags/$version"],
      "exclude": []
    }
  },
  "rules": [
    {"type": "update"},
    {"type": "deletion"}
  ]
}
JSON
)
ruleset_id=$(jq -er .id <<<"$ruleset")
ruleset=$(gh api "repos/$repo/rulesets/$ruleset_id")
jq -e --arg ref "refs/tags/$version" '
  .target == "tag"
  and .enforcement == "active"
  and .conditions.ref_name.include == [$ref]
  and .conditions.ref_name.exclude == []
  and ([.rules[].type] | sort) == ["deletion", "update"]
  and ((.bypass_actors // []) | length) == 0
' <<<"$ruleset" >/dev/null

gh release create "$version" \
  "$zip_path" "$release_dir/$asset.sha256" \
  --repo "$repo" --verify-tag --title "Nexus $version" --notes-from-tag
release=$(gh api "repos/$repo/releases/tags/$version")
jq -e --arg zip "$asset" --arg sum "$asset.sha256" \
  --arg digest "sha256:$outer_sha256" '
    .draft == false
    and (.assets | any(.name == $zip and .digest == $digest))
    and (.assets | any(.name == $sum))
  ' <<<"$release" >/dev/null
printf 'release_sha=%s\ntag_object=%s\nasset_sha256=%s\n' \
  "$release_sha" "$tag_object" "$outer_sha256"
```

GitHub Release publication does not create a DOI by itself. The completed
`v0.1.0` archive used a manual production-Zenodo deposit and received DOI
`10.5281/zenodo.21343496`. A future version must obtain and verify its own
version DOI; never reuse the `v0.1.0` DOI as though it identified new bytes.

For a future manual Zenodo deposit, use the production API only after the token
is available. The evidence ZIP, not merely GitHub's source snapshot, must
appear in the deposit's `files[]` before publication. Archive an explicit tag
source ZIP and its checksum alongside the evidence ZIP and its checksum:

```bash
: "${ZENODO_ACCESS_TOKEN:?Zenodo token or enabled integration is required}"
zenodo=https://zenodo.org/api
auth="Authorization: Bearer $ZENODO_ACCESS_TOKEN"
source_asset="nexus-source-$version.zip"
source_zip="$release_dir/$source_asset"
gh api "repos/$repo/zipball/$version" >"$source_zip"
source_sha256=$(sha256sum "$source_zip" | cut -d ' ' -f1)
printf '%s  %s\n' "$source_sha256" "$source_asset" \
  >"$release_dir/$source_asset.sha256"

deposit=$(curl -fsS -X POST -H "$auth" -H 'Content-Type: application/json' \
  -d '{}' "$zenodo/deposit/depositions")
deposit_id=$(jq -er .id <<<"$deposit")
bucket=$(jq -er .links.bucket <<<"$deposit")
metadata_envelope="$release_dir/zenodo-metadata.json"
jq '{metadata: .}' .zenodo.json >"$metadata_envelope"
curl -fsS -X PUT -H "$auth" -H 'Content-Type: application/json' \
  --data-binary @"$metadata_envelope" \
  "$zenodo/deposit/depositions/$deposit_id" >/dev/null
curl -fsS -X PUT -H "$auth" --upload-file "$zip_path" \
  "$bucket/$asset" >/dev/null
curl -fsS -X PUT -H "$auth" --upload-file "$release_dir/$asset.sha256" \
  "$bucket/$asset.sha256" >/dev/null
curl -fsS -X PUT -H "$auth" --upload-file "$source_zip" \
  "$bucket/$source_asset" >/dev/null
curl -fsS -X PUT -H "$auth" --upload-file "$release_dir/$source_asset.sha256" \
  "$bucket/$source_asset.sha256" >/dev/null

draft=$(curl -fsS -H "$auth" "$zenodo/deposit/depositions/$deposit_id")
jq -e --arg evidence "$asset" --arg source "$source_asset" '
  (.files | any((.filename // .key // "") == $evidence))
  and (.files | any((.filename // .key // "") == ($evidence + ".sha256")))
  and (.files | any((.filename // .key // "") == $source))
  and (.files | any((.filename // .key // "") == ($source + ".sha256")))
' \
  <<<"$draft" >/dev/null
draft_evidence_url=$(jq -er --arg evidence "$asset" '
  .files[]
  | select((.filename // .key // "") == $evidence)
  | .links.download // .links.self
' <<<"$draft")
draft_evidence="$release_dir/zenodo-draft-$asset"
curl -fsSL -H "$auth" "$draft_evidence_url" -o "$draft_evidence"
test "$(sha256sum "$draft_evidence" | cut -d ' ' -f1)" = "$outer_sha256"
draft_source_url=$(jq -er --arg source "$source_asset" '
  .files[]
  | select((.filename // .key // "") == $source)
  | .links.download // .links.self
' <<<"$draft")
draft_source="$release_dir/zenodo-draft-$source_asset"
curl -fsSL -H "$auth" "$draft_source_url" -o "$draft_source"
test "$(sha256sum "$draft_source" | cut -d ' ' -f1)" = "$source_sha256"
published=$(curl -fsS -X POST -H "$auth" \
  "$zenodo/deposit/depositions/$deposit_id/actions/publish")
jq -e --arg evidence "$asset" --arg source "$source_asset" '
  (.files | any((.filename // .key // "") == $evidence))
  and (.files | any((.filename // .key // "") == $source))
' \
  <<<"$published" >/dev/null
record_id=$(jq -er '.record_id // .id' <<<"$published")
public_record=$(curl -fsS "$zenodo/records/$record_id")
jq -e --arg zip "$asset" \
  '.files | any((.filename // .key // "") == $zip)' \
  <<<"$public_record" >/dev/null
download_url=$(jq -er --arg zip "$asset" '
  .files[]
  | select((.filename // .key // "") == $zip)
  | .links.download // .links.self
' <<<"$public_record")
archived_zip="$release_dir/zenodo-$asset"
curl -fsSL "$download_url" -o "$archived_zip"
test "$(sha256sum "$archived_zip" | cut -d ' ' -f1)" = "$outer_sha256"
source_download_url=$(jq -er --arg source "$source_asset" '
  .files[]
  | select((.filename // .key // "") == $source)
  | .links.download // .links.self
' <<<"$public_record")
archived_source="$release_dir/zenodo-$source_asset"
curl -fsSL "$source_download_url" -o "$archived_source"
test "$(sha256sum "$archived_source" | cut -d ' ' -f1)" = "$source_sha256"
doi=$(jq -er '.doi // .metadata.doi' <<<"$public_record")
printf 'published_doi=%s\n' "$doi"
```

After publication, query the public Zenodo record again and require its
`files[]` to contain `$asset`; downloading that file must reproduce
`outer_sha256`. Only then record the DOI in the GitHub Release notes, the Zenodo
record, and a later `main`/version metadata update. Never move or rewrite the
already released tag to insert a DOI minted after its source was sealed. The
`v0.1.0` release followed this rule: its tag remains unchanged, while later
`main` metadata records its verified DOI.

## Troubleshooting and retained limits

A registry, package-server, or Docker Hub error during initial image
construction is an external acquisition failure, not a model, kernel, QEMU, or
Stage 7B result. Retry only after confirming that no source changed. A failure
after the verification start record is issued cannot be repaired into a
successful manifest by focused commands; rerun the full gate.

The release does not archive derived OCI images or every upstream package
server. Long-term first-build availability therefore depends on the pinned
objects remaining obtainable unless the release archive is later augmented
with OCI images or dependency caches. This limitation does not weaken the
byte-level auditability of the published complete evidence bundle.
