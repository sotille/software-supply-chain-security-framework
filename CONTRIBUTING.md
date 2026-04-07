# Contributing to the Techstream Software Supply Chain Security Framework

Thank you for your interest in contributing. This repository covers the full spectrum of software supply chain security: dependency management, build system hardening, artifact signing and verification, SBOM generation and management, SLSA framework implementation, and deployment-time integrity enforcement. The supply chain security space evolves rapidly with new standards, tooling, and regulatory requirements — timely, accurate contributions are especially valuable here.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [What We Welcome](#what-we-welcome)
- [What We Do Not Accept](#what-we-do-not-accept)
- [How to Contribute](#how-to-contribute)
- [Documentation Standards](#documentation-standards)
- [Review Process](#review-process)
- [License](#license)

---

## Code of Conduct

All contributors are expected to engage professionally and constructively. Contributions that are dismissive, personal, or unprofessional will not be reviewed.

---

## What We Welcome

- **SLSA framework updates** — as SLSA specifications evolve (levels 1–4, track-based model), updates to implementation guidance reflecting the current specification are critical.
- **SBOM tooling and format guidance** — CycloneDX and SPDX format updates, Syft and cdxgen configuration guidance, SBOM attestation patterns, and VEX document workflows.
- **Sigstore and Cosign implementation examples** — keyless signing workflows, policy verification examples, Rekor transparency log integration.
- **Dependency confusion attack mitigations** — updated patterns for private registry configuration, namespace protection, and package name squatting prevention.
- **Regulatory alignment** — EO 14028, CISA guidance, EU Cyber Resilience Act, and NIST SSDF mapping updates.
- **New threat scenarios** — well-documented, real-world supply chain attack patterns (SolarWinds, XZ Utils, Log4Shell-class scenarios) and the specific controls that mitigate them.
- **OPA/Kyverno policy examples** — admission controller policies for supply chain control enforcement with working, tested configurations.
- **SBOM management platform guidance** — Dependency-Track, Grype, and other SBOM management platform integration patterns.

---

## What We Do Not Accept

- Vendor promotional content.
- Untested policy configurations that could cause production outages if applied directly.
- Scope beyond software supply chain security (CI/CD pipeline design → secure-ci-cd-reference-architecture, runtime security → cloud-security-devsecops).
- Major structural changes without prior issue discussion.

---

## How to Contribute

### Reporting Issues

Use GitHub Issues to report: outdated SLSA specification references, incorrect Sigstore/Cosign command syntax, gaps in SBOM format coverage, or regulatory mapping inaccuracies.

### Submitting Pull Requests

1. Fork and branch from `main` with a descriptive branch name.
2. Verify all command-line examples against the current stable version of the referenced tool.
3. For policy configurations (Kyverno, OPA), include a note on which Kubernetes version and tool version the policy was validated against.
4. Open a pull request with a clear description, affected sections, and references.

---

## Documentation Standards

- Technical tone for security architects, DevSecOps engineers, and platform engineers.
- Command-line examples should include the tool version they were validated against as a comment.
- Mermaid diagrams for trust chain flows, SBOM lifecycle diagrams, and signing verification flows.
- ATX headers, fenced code blocks with language identifiers, relative internal links.

---

## Review Process

Pull requests are reviewed for technical accuracy, specification alignment, and scope. Given the regulatory sensitivity of this domain, technical accuracy review is particularly thorough. Initial responses within 5 business days.

---

## License

By contributing, you agree your contributions will be licensed under the [Apache License 2.0](LICENSE).
