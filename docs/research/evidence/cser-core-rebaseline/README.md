# CSER Core rebaseline evidence archive

This directory retains source-bound receipt preimages, CI dispositions, and the
final verification log in Git. Large QEMU images, raw media, and debug traces
remain workflow artifacts and are named and hashed by the retained receipts.

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

## Replacement candidate C2 CI failure

- Revision: `2e209bd738a788b174c18b73fa9103d8d65b4bf9`
- Receipt:
  `2e209bd738a788b174c18b73fa9103d8d65b4bf9/combined-receipt.txt`
- Clean local receipt SHA-256:
  `41a331716873a61288ab0a624551a54886cbd0d0802d1fa11f975b226c0c0356`
- CI record:
  `2e209bd738a788b174c18b73fa9103d8d65b4bf9/ci-failure.txt`
- Disposition: the clean local four-boot seal passed. Exact-C2 CI passed quick,
  the complete core gate, both focused guests, and TPM provisioning. The first
  production QEMU process then failed before guest execution because swtpm
  received `CMD_SET_DATAFD` without its Unix ancillary data socket. C2 is valid
  local evidence for its revision, not the final release seal.

## Final replacement C3

- Revision: `16e87b0f94b5270760dc02048fb4191bf877df71`
- Clean local receipt:
  `16e87b0f94b5270760dc02048fb4191bf877df71/combined-receipt.txt`
- Clean local receipt SHA-256:
  `52aed92515920c543814bef0a842141bdfcd7c44ce1c3d8c030935ab4498adb5`
- Exact-C3 CI receipt:
  `16e87b0f94b5270760dc02048fb4191bf877df71/ci-combined-receipt.txt`
- Exact-C3 CI receipt SHA-256:
  `e3e46c8efdd6755c7f750579f925251b3912b3f1e7a7fa35a92765a3cc995728`
- CI disposition:
  `16e87b0f94b5270760dc02048fb4191bf877df71/ci-success.txt`
- Complete merged CI log, losslessly compressed:
  `16e87b0f94b5270760dc02048fb4191bf877df71/ci-complete.log.gz`
- Uncompressed log SHA-256:
  `54ccd9155788dbcc7f3e83d20ae2cb69bbfbae66be66035132362b96c2d71121`
- Artifact retention caveat: the success upload omitted the hidden, zero-byte
  `tpmstate/.lock`. This archive retains the artifact's byte-exact state file
  plus the reconstructed empty lock under
  `16e87b0f94b5270760dc02048fb4191bf877df71/ci-tpmstate/`. That tree reconstructs
  the receipt's TPM state hash
  `a3fb319391f07553c4e434addada8394ffc1c06ec45199e7a1969a5255e6a14a`.
- Disposition: the clean local seal and exact-C3 GitHub run both passed the
  complete core/model/property/Loom gate, focused reply and DMA guests, and all
  four production boots. The release ledger records the bounded claims and
  non-claims. The focused same-boot DMA slice's logical core-resource reuse does
  not authorize retained cross-reboot PFN/IOVA/quarantined queue or physical
  address reuse.
