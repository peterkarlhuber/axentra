# Shared security test vectors (vendored copy)

`security-vectors.json` is an unchanged copy of the shared security test vectors (MUP-ONA MP-A8, finding VB-7):
egress, ID token and redaction cases that Axentra and Nodestro both run against their own implementations. The corpus
is maintained in another repository; Axentra keeps this copy so that it has no code, test or install dependency on
it. `tests/test_security_vectors.py` (T-VEC-2) runs the `egress` vectors against the webhook target check
(`axentra.events.http_client`), the `jwt` vectors against `OidcClient.verify` and the `redaction` vectors against
`axentra.core.redaction.redact`, and first checks that the copy has the SHA-256 and version recorded below.
Vectors Axentra judges differently are listed in the file's `known_differences` (platform `axentra`) with their
reasons.

Origin: `https://github.com/peterkarlhuber/nodestro-runtime`, file `tests/vectors/security-vectors.json`, copied from
commit `9ee46fe840e0eb0425cd10189ec83721be63c717` (branch `mup/a8-security-vectors`)
Version: `1`
SHA-256: `f94167380a97c42ef2d02de8bbe10a899f00fe813c136998c9614c776e571283`

## Updating the copy

Replace `security-vectors.json` with the new canonical file unchanged (never edit it by hand), then update the origin
commit, `Version` and `SHA-256` above (`sha256sum tests/vectors/security-vectors.json`) and run
`pytest tests/test_security_vectors.py`. A new deviation of Axentra is fixed, or listed with its reason in the
canonical file's `known_differences` first. The canonical repository's CI compares this copy on `master` with its
file, so this update merges before the canonical change.
