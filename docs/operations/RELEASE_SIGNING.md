# Release signing (proposed procedure)

Status: **proposal, not in use.** No image or artifact of Axentra is signed today. Signing a release needs the
owner's release approval and a decision on key management (below); nothing in CI signs or publishes anything.

## What gets signed

- The container image by its **platform manifest digest** (`linux/amd64`), which is reproducible: two builds of
  one commit give the same digest (DEPLOYMENT.md, "Reproducible build"). The image index is not reproducible
  (BuildKit's provenance attestation), so signatures and release notes name the platform manifest digest.
- An attestation with the image's CycloneDX SBOM (`/opt/axentra/sbom.cdx.json`).
- Optionally the source archive of the release commit (`cosign sign-blob`).

## Tooling

[cosign](https://github.com/sigstore/cosign) v2, run from its pinned container image, with a key pair (not
keyless signing): keyless signing writes the signer identity to the public Rekor transparency log, which is a
publication and needs the owner's decision.

```bash
COSIGN="docker run --rm -u 0 --network host -v $PWD:/k -w /k -e COSIGN_PASSWORD ghcr.io/sigstore/cosign/cosign:v2.4.1"
IMAGE=<registry>/axentra@sha256:<platform manifest digest>

$COSIGN sign --yes --key cosign.key --tlog-upload=false "$IMAGE"
docker run --rm --entrypoint cat "$IMAGE" /opt/axentra/sbom.cdx.json > sbom.cdx.json
$COSIGN attest --yes --key cosign.key --tlog-upload=false --type cyclonedx --predicate sbom.cdx.json "$IMAGE"

# Consumers verify with the public key only:
$COSIGN verify --key cosign.pub --insecure-ignore-tlog "$IMAGE"
$COSIGN verify-attestation --key cosign.pub --insecure-ignore-tlog --type cyclonedx "$IMAGE"
```

`--tlog-upload=false` keeps the signature off the public transparency log; verification then needs
`--insecure-ignore-tlog` and relies on the distributed public key alone. Dropping both flags is part of the
key-management decision.

A dry run on 2026-11-14 signed and attested a release-candidate image in a local registry (`registry:2` on
`127.0.0.1`) with a throwaway key; `verify` and `verify-attestation` passed and verification with another key
failed (`no matching signatures`). The throwaway key was never used for anything else.

## Open decisions (owner)

1. **Key custody:** where the private key lives (offline hardware token, a KMS such as `awskms://` /
   `gcpkms://` / `hashivault://`, or a passphrase-protected file in a password manager), who may sign, and the
   rotation and revocation process.
2. **Public key distribution:** for example `cosign.pub` in this repository and on the website, so that
   customers can verify.
3. **Transparency log:** sign with `--tlog-upload=false` (private) or upload to the public Rekor log.
4. **Registry:** where release images are pushed (none is set up; no image has been published).
