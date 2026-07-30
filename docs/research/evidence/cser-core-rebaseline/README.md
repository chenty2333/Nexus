# CSER Core rebaseline evidence archive

This directory retains small, source-bound receipt preimages and CI disposition
records in Git. Large QEMU images, raw media, and debug logs remain workflow
artifacts and are named and hashed by the retained receipts.

## Historical cutover A

- Revision: `c06e9f43e931ed3f130da6dfcf29452a45406152`
- Receipt:
  `c06e9f43e931ed3f130da6dfcf29452a45406152/combined-receipt.txt`
- Receipt SHA-256:
  `e0f959e5c4027fb3952384b77de38b6c97e8c5bdd5a9c20f109c515361cf6f1e`
- Disposition: clean local four-boot receipt retained as valid evidence for A.
  It is not the final release receipt after the swtpm harness changed.

## Attestation B CI failure

- Revision: `de13e69363e59843ba5e0302fd983db27f6fd709`
- Record: `de13e69363e59843ba5e0302fd983db27f6fd709/ci-failure.txt`
- Disposition: `./x test --quick` passed. `./x verify` passed the complete
  core/model/property/Loom gate, then failed before TPM provisioning completed
  or any production boot because Ubuntu 24.04's swtpm 0.7.3 rejects the optional
  `--tpmstate ...,lock` parameter.

This negative result is retained because it invalidated B as a complete release
attestation and caused a replacement clean seal. No entry here promotes B to
PASS.

## Replacement candidate C1 CI failure

- Revision: `4b59c47be381ef44c56350f018c46358c59b61e2`
- Receipt:
  `4b59c47be381ef44c56350f018c46358c59b61e2/combined-receipt.txt`
- Clean local receipt SHA-256:
  `785ef0e13c505cbd324773e4439f9bbb51496c46d01f775ae303093011c844c8`
- CI record:
  `4b59c47be381ef44c56350f018c46358c59b61e2/ci-failure.txt`
- Disposition: the clean local four-boot seal passed. Exact-C1 CI passed quick,
  the complete core gate, and both focused guests, then swtpm 0.7.3 rejected
  the v0.8 `disable-auto-shutdown` flag before provisioning or production
  boot. C1 is valid local evidence for its revision, not the final release seal.

A later directory must record the capability-negotiated replacement receipt
and exact CI PASS before the release ledger can return to `SEALED`.
