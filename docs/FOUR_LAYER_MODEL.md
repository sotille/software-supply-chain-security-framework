# The Four-Layer Software Supply Chain Integrity Model

This document is the repo-resident reference for the four-layer integrity model. The model is the architectural foundation of this framework and is explained in detail in the May 2026 Medium article *"The Four Layers of Software Supply Chain Integrity: Why Most SBOMs Are Theater — and What Actually Works."*

## The four layers

| Layer | Question it answers | Federal alignment |
|---|---|---|
| 1. Provenance | *What is in the software I ship?* | EO 14028 §4(e); NIST SP 800-218 PS.3 |
| 2. Integrity | *Has it been tampered with since the author signed it?* | EO 14028 §4(e); NIST SSDF PW.4 |
| 3. Trust | *Who built it, and under what conditions?* | SLSA framework; CISA Secure-by-Design |
| 4. Continuous attestation | *Is this still true at runtime?* | EO 14306; NIST SP 1800-44 |

Each layer requires the previous one. A signed artifact (Layer 2) without an SBOM (Layer 1) tells you the binary is authentic but not what it contains. A SLSA build attestation (Layer 3) without runtime verification (Layer 4) is meaningless if nobody checks before deploying.

## Layer 1 — Provenance

- SBOM generation runs in CI on every build (CycloneDX or SPDX)
- SBOMs include direct and transitive dependencies, with version, license, and supplier
- A central index lets you query "which artifacts contain CVE-X?" in under 60 seconds

## Layer 2 — Integrity

- Sigstore + Cosign for keyless signing using OIDC identity
- Signatures cover the artifact and the SBOM
- A transparency log (Rekor) records every signing event
- Verification is enforced at deploy time, not at audit time

## Layer 3 — Trust (SLSA)

- Every build produces a cryptographically signed attestation
- Attestation records source repository commit, builder identity, build environment, and build inputs
- Consumers can independently verify the entire build context

## Layer 4 — Continuous attestation

- Admission controllers (Kubernetes) verify SBOM, signature, and SLSA provenance at scheduling time
- Periodic fleet scans re-verify deployed artifacts against the central inventory
- SBOM diffing detects when a deployed artifact's runtime composition diverges from its build-time SBOM
- Vulnerability re-scoring runs continuously

## See also

- `docs/SBOM_FORMAT_GUIDE.md` — practical guidance on CycloneDX vs SPDX
- `docs/FEDERAL_ALIGNMENT.md` (if present) — explicit federal-standards alignment
