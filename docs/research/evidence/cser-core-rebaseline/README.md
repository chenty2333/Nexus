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
attestation and caused a replacement clean seal. A later directory records that
replacement receipt and exact CI result; no entry here promotes B to PASS.
