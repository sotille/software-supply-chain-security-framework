# SBOM Format Guide — CycloneDX vs SPDX

This document provides practical guidance for choosing and implementing SBOM formats in your supply chain.

## Quick comparison

| Aspect | CycloneDX | SPDX |
|---|---|---|
| Steward | OWASP | Linux Foundation |
| Primary use case | Application security, vulnerability management | Software licensing, compliance |
| Common file extension | `.cdx.json`, `.cdx.xml` | `.spdx.json`, `.spdx` |
| VEX support | Native (CycloneDX VEX) | Via separate document |
| Tooling maturity | Excellent for security ecosystem | Excellent for licensing tooling |
| EO 14028 acceptance | Yes (NTIA-recognized) | Yes (NTIA-recognized) |

## Recommendation

**Pick one and standardize.** Producing both badly is worse than producing one well. For most teams in cloud-native / security-driven environments, CycloneDX integrates more naturally with vulnerability management tooling (Dependency-Track, Trivy, Grype). For organizations with strong license compliance focus, SPDX is the natural choice.

## Implementation checklist

- [ ] Choose format and document the decision in your architecture record
- [ ] Add SBOM generation to every CI build (Syft, CycloneDX gradle/maven plugins, Anchore SBOM, etc.)
- [ ] Store SBOMs alongside artifacts in your registry (or in an SBOM-specific store)
- [ ] Build a queryable index — Dependency-Track is the open-source reference for CycloneDX; alternative: custom datastore
- [ ] Verify SBOM completeness (transitive deps, license info, version pinning) before signing
- [ ] Sign the SBOM together with the artifact (Cosign supports this natively)
