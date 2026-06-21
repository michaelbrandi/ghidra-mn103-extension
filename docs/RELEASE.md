# Release Checklist

This project currently treats the checked-in `data/languages/mn103.slaspec`
and `data/languages/mn103.sla` files as the release baseline. The generator is
kept for reconciliation work and is not the authoritative release input.

## Supported Target

- Ghidra: 12.0.4 PUBLIC
- Java in CI: Temurin 21
- Language ID: `mn10300:LE:32:default`

## Before Tagging

Run the local checks that match the intended release confidence level:

```bash
GHIDRA_INSTALL_DIR=/Users/mba/Applications/ghidra_12.0.4_PUBLIC \
  ./tools/rebuild_mn103_extension.sh

GHIDRA_INSTALL_DIR=/Users/mba/Applications/ghidra_12.0.4_PUBLIC \
  ./tools/run_instruction_golden.sh

GHIDRA_INSTALL_DIR=/Users/mba/Applications/ghidra_12.0.4_PUBLIC \
  ./tools/run_abi_golden.sh
```

For a heavier local pass, run:

```bash
GHIDRA_INSTALL_DIR=/Users/mba/Applications/ghidra_12.0.4_PUBLIC \
  ./tools/check_mn103_corpus.sh
```

## Tagging A Release Candidate

Use release-candidate tags until the extension has had broader human review and
field testing:

```bash
git tag -a v0.7.0-rc1 -m "MN103 Ghidra extension v0.7.0-rc1"
git push origin main v0.7.0-rc1
```

If a published release-candidate tag fails in CI, leave it in place and cut the
next candidate tag after the fix. Do not rewrite a pushed release tag.

Pushing a `v*` tag starts the `MN103 Release` workflow. That workflow builds
the extension, runs smoke analysis plus both golden checks, uploads the release
artifacts, and creates a draft GitHub prerelease.

## Release Artifacts

The release workflow publishes:

- `ghidra-mn103-extension-<tag>.zip`
- `SHA256SUMS`

Keep GitHub prereleases as drafts until the workflow has passed and the artifact
has been installed in a clean Ghidra profile at least once.
