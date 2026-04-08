# Software Supply Chain Security Framework

> A comprehensive, enterprise-grade framework for securing the software supply chain — from source code through build, packaging, distribution, and deployment — using SLSA, SBOM, artifact signing, and provenance-based trust.

---

## Table of Contents

- [Overview](#overview)
- [Scope](#scope)
- [Key Topics Covered](#key-topics-covered)
- [Documentation](#documentation)
- [How to Use This Framework](#how-to-use-this-framework)
- [Related Resources](#related-resources)
- [License](#license)

---

## Overview

Software supply chain attacks have emerged as one of the most significant threats in modern cybersecurity. The SolarWinds compromise demonstrated that adversaries can achieve widespread impact by targeting the build and distribution infrastructure of widely deployed software. Log4Shell showed that a single vulnerability in a ubiquitous open source library could expose hundreds of thousands of systems. The XZ Utils backdoor revealed that even long-standing open source projects can be targeted through patient, sophisticated social engineering of maintainers.

These incidents share a common thread: the attack surface is not the application itself, but the *components and processes that produce and deliver* the application. Securing this supply chain requires a fundamentally different security model — one that treats every dependency, build step, and artifact as a potential threat vector, and builds cryptographic trust chains from source to deployment.

The **Software Supply Chain Security Framework** provides the conceptual foundation, architectural patterns, controls library, and implementation guidance needed to establish and mature a supply chain security program. It draws from SLSA (Supply chain Levels for Software Artifacts), NIST SSDF, Executive Order 14028, the EU Cyber Resilience Act, and emerging industry practices from organizations including Google, CNCF, and the Open Source Security Foundation (OpenSSF).

---

## Scope

This framework covers the full software supply chain lifecycle:

- **Source security** — protecting source code integrity, managing contributor access, and detecting malicious code changes
- **Dependency security** — managing open source and third-party dependencies, including vulnerability tracking, license compliance, and supply chain risk assessment
- **Build security** — securing the build environment, establishing hermetic and reproducible builds, and generating build provenance
- **Artifact security** — signing artifacts, generating and attesting SBOMs, and maintaining integrity through the distribution chain
- **Distribution security** — securing artifact registries, enforcing access controls, and validating artifacts at distribution
- **Deployment security** — verifying artifact integrity and provenance at deployment time, enforcing admission control policies

**Out of scope:** Runtime application security, network security controls, and identity and access management for production systems (addressed in separate framework documents).

---

## Key Topics Covered

| Topic | Description |
|---|---|
| **Threat landscape** | SolarWinds, Log4Shell, XZ Utils case studies; attack taxonomy |
| **Regulatory requirements** | EO 14028, EU CRA, NIST SSDF, PCI-DSS |
| **SLSA framework** | Levels 1–4 explained with implementation guidance |
| **SBOM** | CycloneDX and SPDX formats, generation tooling, lifecycle management |
| **Artifact signing** | Cosign, Sigstore, Notary v2 — signing and verification patterns |
| **Provenance** | Build provenance generation, attestation, and verification |
| **Dependency management** | Pinning, lockfiles, private mirrors, vulnerability scanning |
| **Build security** | Hermetic builds, reproducible builds, build system hardening |
| **Registry security** | Access control, immutable tags, vulnerability scanning |
| **Policy enforcement** | OPA, Kyverno admission control, deployment gates |
| **Third-party risk** | Vendor assessment, open source risk management, maintainer health |
| **Implementation roadmap** | 12-month program development with quick wins and maturity milestones |

---

## Documentation

| Document | Description |
|---|---|
| [Introduction](docs/introduction.md) | Supply chain threat landscape, attack categories, regulatory environment, key terminology |
| [Architecture](docs/architecture.md) | Supply chain security reference architecture, SLSA levels, SBOM architecture, Sigstore/Cosign integration, trust chain design |
| [Framework](docs/framework.md) | Full controls library — dependency security, SBOM, artifact signing, build security, SLSA compliance, registry security, policy enforcement |
| [SBOM Guide](docs/sbom-guide.md) | CycloneDX vs SPDX format comparison, tool selection matrix (Syft, Trivy, cdxgen), CI/CD integration patterns, NTIA minimum elements |
| [SBOM at Scale](docs/sbom-at-scale.md) | Enterprise SBOM storage architecture, lifecycle management, querying and analytics, Dependency-Track capacity planning, regulatory reporting |
| [VEX and SBOM Lifecycle](docs/vex-and-sbom-lifecycle.md) | VEX workflow for vulnerability exploitability analysis; SBOM versioning, storage architecture, patch cycle integration, retention policy |
| [Implementation](docs/implementation.md) | Phased implementation, SBOM tooling (Syft, Trivy, cdxgen), Sigstore/Cosign deployment, SLSA progression, private registry setup |
| [Open Source Component Assessment](docs/open-source-component-assessment.md) | Structured framework for assessing OSS dependency health, security posture, supply chain integrity, and license risk before introduction and during continuous monitoring |
| [Incident Response Playbook](docs/incident-response-playbook.md) | Four detailed IR playbooks for: compromised OSS dependency, build system compromise, artifact tampering, pipeline credential compromise |
| [License Compliance Integration](docs/license-compliance-integration.md) | License risk classification (Tier 1–4), automated license scanning in CI/CD, SBOM-driven license auditing, attribution generation, and exception management |
| [Best Practices](docs/best-practices.md) | 30+ best practices by supply chain layer: source, dependencies, build, artifacts, distribution, deployment |
| [Roadmap](docs/roadmap.md) | 12-month security roadmap, quick wins, SLSA maturity progression, regulatory compliance milestones, KPIs |

---

## How to Use This Framework

Organizations at different stages of supply chain security maturity will use this framework differently.

**Starting from scratch:** Begin with the [Introduction](docs/introduction.md) to understand the threat landscape and build the business case for investment. Then use the [Architecture](docs/architecture.md) to design the target state, the [Framework](docs/framework.md) to define your controls, and the [Roadmap](docs/roadmap.md) to plan a realistic 12-month program.

**Improving an existing program:** Use the [Framework](docs/framework.md) controls library to identify gaps in your current controls, the [Best Practices](docs/best-practices.md) document for actionable improvement guidance, and the [Roadmap](docs/roadmap.md) SLSA maturity progression to target higher assurance levels.

**Responding to a specific regulatory requirement (EO 14028, EU CRA):** The [Introduction](docs/introduction.md) maps requirements to relevant framework controls. Use the [Implementation](docs/implementation.md) guide to deploy the specific tooling required to evidence compliance.

**Recommended reading order:**

1. [Introduction](docs/introduction.md) — understand the threat landscape and regulatory context
2. [Architecture](docs/architecture.md) — design the target security architecture
3. [Framework](docs/framework.md) — define the controls program
4. [Implementation](docs/implementation.md) — execute the technical implementation
5. [Best Practices](docs/best-practices.md) — continuously improve
6. [Roadmap](docs/roadmap.md) — plan the maturity journey

---

## Related Resources

### Standards and Frameworks

- [SLSA Framework](https://slsa.dev) — Supply chain Levels for Software Artifacts
- [NIST SSDF (SP 800-218)](https://csrc.nist.gov/publications/detail/sp/800-218/final) — Secure Software Development Framework
- [NIST SP 800-161r1](https://csrc.nist.gov/publications/detail/sp/800-161/rev-1/final) — Cybersecurity Supply Chain Risk Management
- [OpenSSF Scorecard](https://securityscorecards.dev) — Open source project security assessment
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/) — SBOM standard
- [SPDX Specification](https://spdx.dev/specifications/) — SBOM standard

### Tooling

- [Sigstore / Cosign](https://sigstore.dev) — Artifact signing and verification
- [Syft](https://github.com/anchore/syft) — SBOM generation
- [Grype](https://github.com/anchore/grype) — Vulnerability scanning
- [Trivy](https://github.com/aquasecurity/trivy) — Container and filesystem security scanner
- [cdxgen](https://github.com/CycloneDX/cdxgen) — CycloneDX SBOM generator
- [in-toto](https://in-toto.io) — Supply chain integrity framework
- [Tekton Chains](https://tekton.dev/docs/chains/) — Kubernetes-native supply chain security

### Regulatory Documents

- [Executive Order 14028](https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity) — Improving the Nation's Cybersecurity
- [EU Cyber Resilience Act](https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act) — EU cybersecurity requirements for digital products

---

## Learning Resources

The Techstream Book Series and hands-on lab companion extend the concepts in this framework with structured learning, exercises, and guided implementation walkthroughs.

- **[Book 2: Securing CI/CD & the Software Supply Chain](https://www.techstream.app/learn)** — The primary book volume aligned with this framework. Covers SLSA level advancement, SBOM generation and lifecycle, VEX workflows, Sigstore/Cosign signing, and hermetic builds.
- **[Hands-On Labs (techstream-learn/book-2-cicd-supply-chain/)](https://www.techstream.app/learn)** — Practical exercises including SBOM generation with CycloneDX, Cosign artifact signing, and SLSA provenance attestation.
- **[Book Series Overview (VOLUMES.md)](../techstream-books/VOLUMES.md)** — Index of all five Techstream volumes covering DevSecOps foundations, CI/CD security, cloud security, release governance, and AI and agentic systems security.
- **[Techstream Platform](https://www.techstream.app)** — The central portal for all Techstream frameworks, documentation, and learning resources.

---

## License

Copyright 2024 Techstream

Licensed under the Apache License, Version 2.0. See the [LICENSE](LICENSE) file for the full license text.
