# Open Source Component Assessment

Consuming open source software is unavoidable in modern software delivery — the average enterprise application depends on hundreds of third-party packages. Each dependency is a trust decision. Organizations that make those decisions implicitly, without a defined process, inherit risk they cannot measure. This document provides a structured framework for assessing the security posture, health, and trustworthiness of open source components before introducing them into the software supply chain, and for continuously monitoring components already in use.

---

## Scope

This framework applies to:

- **New dependency introduction** — when a developer proposes to add a new open source package
- **Periodic dependency review** — scheduled assessment of existing dependencies
- **Incident-triggered review** — when a supply chain incident (e.g., maintainer compromise, malicious package) triggers reassessment of similar components
- **Dependency upgrades** — when a major version change significantly alters the codebase or maintainer structure of a dependency

The framework covers all package ecosystems: npm (JavaScript), PyPI (Python), Maven/Gradle (Java/Kotlin), NuGet (.NET), Go modules, Cargo (Rust), RubyGems, and system-level packages.

---

## Assessment Dimensions

Open source components are assessed across six dimensions. Each dimension is scored independently, and the lowest-scoring dimension governs the overall risk tier.

### Dimension 1: Maintainer Health

A component's security is directly tied to the capacity and intent of its maintainers. Unmaintained packages accumulate vulnerabilities without remediation.

| Indicator | Healthy | Caution | At Risk |
|-----------|---------|---------|---------|
| Last commit date | < 6 months ago | 6–18 months ago | > 18 months ago |
| Open critical/high issues | < 5 unaddressed | 5–20 unaddressed | > 20 or unknown |
| Security advisory response time | CVEs patched within 30 days | 30–90 days | > 90 days or no response |
| Active maintainer count | ≥ 3 active | 2 active | 1 (bus factor = 1) |
| Has a published security policy (SECURITY.md) | Yes | No, but responsive | No |
| Signed releases | Yes (GPG or Sigstore) | Partial | No |
| Has a CVE/security track record | Clean or promptly patched | Multiple unpatched | Repeated disclosure failures |

**Bus factor = 1 is a critical risk.** A single maintainer account compromise can result in a malicious release to all downstream consumers (XZ Utils pattern).

**Automated check:**

```bash
# Use OpenSSF Scorecard to get an objective maintainer health signal
scorecard --repo=github.com/owner/project --format=json | \
  jq '.checks[] | select(.name == "Maintained") | {score: .score, reason: .reason}'
```

---

### Dimension 2: Security Posture

Does the project demonstrate security-conscious development practices?

| Indicator | Healthy | Caution | At Risk |
|-----------|---------|---------|---------|
| OpenSSF Scorecard score | ≥ 7/10 | 4–6/10 | < 4/10 |
| Branch protection enabled | Yes | Partial | No |
| Dependency pinning in CI | Yes | Partial | No |
| Automated vulnerability scanning in CI | Yes | Manual only | None |
| SAST in CI pipeline | Yes | Manual/occasional | None |
| Code signing of releases | Yes | No, but deterministic build | None |
| SLSA level | Level 2+ | Level 1 | Level 0 |

**Key check:**

```bash
# Run OpenSSF Scorecard assessment
scorecard --repo=github.com/owner/project \
  --checks=BranchProtection,CITests,DangerousWorkflow,DependencyUpdateTool,\
Maintained,Pinned-Dependencies,SAST,SecurityPolicy,SignedReleases,Vulnerabilities
```

---

### Dimension 3: Supply Chain Integrity

Can you verify what you are consuming matches what the project published?

| Indicator | Healthy | Caution | At Risk |
|-----------|---------|---------|---------|
| Published SBOM | Yes (CycloneDX or SPDX) | Partial/outdated | None |
| Artifact signature verifiable | Yes (Sigstore/Cosign or GPG) | Tag-only (no signature) | No signature |
| Reproducible build | Verified reproducible | Partial (build scripts published) | No evidence |
| Binary artifacts in source tree | None | Documented | Undocumented binaries present |
| Build process is documented | Yes, hermetic | Partially documented | Undocumented |

Binary blobs in a source repository are a significant indicator of supply chain risk. Undocumented binaries should trigger automatic escalation regardless of other scores.

---

### Dimension 4: License and Legal

License incompatibility can create legal exposure; some licenses impose restrictions on commercial use or derivative works.

| License Category | Examples | Commercial Use | Modification | Distribution Requirement |
|-----------------|---------|----------------|--------------|--------------------------|
| **Permissive** | MIT, Apache 2.0, BSD | Permitted | Permitted | Attribution required |
| **Weak copyleft** | LGPL, MPL | Permitted (linking) | Permitted | Modified files must be open sourced |
| **Strong copyleft** | GPL v2/v3 | Permitted (if open sourced) | Permitted | Entire derived work must be open sourced |
| **Commercial restriction** | SSPL, BSL, Commons Clause | Restricted | Restricted | Review required |
| **No license** | — | Legally ambiguous | Ambiguous | Do not use without explicit permission |

**Approval tiers by license:**

- **Auto-approved:** MIT, Apache 2.0, BSD 2-Clause, BSD 3-Clause, ISC, CC0, Unlicense
- **Legal review required:** LGPL (any version), MPL 2.0, EUPL, CDDL
- **Restricted — architecture review required:** GPL v2 / v3 (for embedded/commercial products), AGPL, SSPL, BSL, Commons Clause
- **Blocked:** No license, unknown license, custom non-OSI-approved license

---

### Dimension 5: Popularity and Community

Community size is a proxy for the number of eyes reviewing the code and the likelihood that vulnerabilities are discovered and reported.

| Indicator | Healthy | Caution | At Risk |
|-----------|---------|---------|---------|
| GitHub stars | > 1,000 | 100–1,000 | < 100 |
| Weekly download count (npm/PyPI) | > 10,000 | 1,000–10,000 | < 1,000 |
| Dependent projects | > 500 (signals ecosystem trust) | 100–500 | < 100 |
| Active contributors (last 12 months) | > 10 | 3–10 | < 3 |
| Backed by a foundation or organization | OSF, CNCF, Apache, Linux Foundation | Corporate-backed | Individual |

Note: popularity does not eliminate risk (Log4Shell was extremely popular); it is one signal among many.

---

### Dimension 6: Functionality Scope

The risk surface of a dependency scales with the access it requires. A dependency that parses config files carries far less risk than one that executes shell commands or makes network requests.

| Functionality Category | Risk Level | Review Required |
|----------------------|------------|-----------------|
| Data parsing (JSON, YAML, XML, CSV) | Low | Standard |
| String manipulation, utilities | Low | Standard |
| Cryptography (implements algorithms) | High | Security engineer review |
| Authentication, session management | High | Security engineer review |
| Network client / HTTP requests | Medium | Security engineer review |
| Shell execution, process spawning | Critical | Architecture review + CISO approval |
| File system access (read/write) | Medium | Security engineer review |
| Browser/DOM manipulation | Medium | Security engineer review |
| Build toolchain / CI plugins | Critical | Architecture review |

---

## Composite Risk Tier

After scoring all six dimensions, the overall component risk tier is assigned:

| Risk Tier | Criteria | Approval Process | Monitoring Frequency |
|-----------|----------|------------------|----------------------|
| **Tier 1 — Approved** | All dimensions healthy; OpenSSF Scorecard ≥ 7; permissive license | Engineering lead approval | Quarterly |
| **Tier 2 — Conditional** | One caution dimension; Scorecard 4–6; legal-review license | Security champion + engineering lead | Monthly |
| **Tier 3 — Restricted** | Any at-risk dimension; Scorecard < 4; bus factor = 1; restricted license | Security engineer + CISO approval | Weekly CVE monitoring |
| **Tier 4 — Blocked** | Critical risk in any dimension; actively compromised; no license; binary blobs | Blocked — requires replacement plan | N/A |

---

## Assessment Workflow

### New Dependency Request

```
Developer opens PR with new dependency
          ↓
Automated gate: SCA scan + OpenSSF Scorecard
          ↓
├── Scorecard ≥ 7 AND license auto-approved AND no known CVEs
│       ↓
│   Auto-approved → Tier 1 → PR may merge
│
├── Scorecard 4–6 OR legal-review license
│       ↓
│   Security champion reviews → Tier 2 conditional approval
│
├── Scorecard < 4 OR bus factor = 1 OR at-risk dimension
│       ↓
│   Security engineer review → Tier 3 or Tier 4
│       ↓
│   Tier 3: documented exception with mitigating controls
│   Tier 4: PR blocked; alternative required
│
└── Binary blob detected OR no license OR actively compromised
        ↓
    Auto-blocked; escalate to security team
```

### Automated Gate in CI

```yaml
# Example: GitHub Actions automated dependency review gate
- name: OpenSSF Scorecard Assessment
  uses: ossf/scorecard-action@v2
  with:
    results_file: scorecard-results.json
    results_format: json
    publish_results: false

- name: Evaluate Scorecard Threshold
  run: |
    SCORE=$(cat scorecard-results.json | jq '.score')
    if (( $(echo "$SCORE < 4.0" | bc -l) )); then
      echo "::error::OpenSSF Scorecard score $SCORE is below threshold 4.0. Security review required."
      exit 1
    fi

- name: Dependency Review (License + CVE)
  uses: actions/dependency-review-action@v4
  with:
    fail-on-severity: high
    deny-licenses: GPL-3.0, AGPL-3.0, SSPL-1.0
    allow-licenses: MIT, Apache-2.0, BSD-2-Clause, BSD-3-Clause, ISC
```

---

## Continuous Monitoring

A one-time assessment at introduction is insufficient. Components must be monitored continuously for:

- **New CVEs** — subscribe to NVD, OSV.dev, and GitHub Advisory Database feeds for all dependencies
- **Maintainer account compromise** — monitor the package registry for unexpected version publications from previously inactive maintainers
- **Ownership transfer** — detect when a package changes ownership on npm, PyPI, or other registries
- **License change** — some projects switch from permissive to restrictive licenses on major versions
- **Repository archival** — GitHub archival is an early signal of abandonment

### Recommended Tooling for Continuous Monitoring

| Tool | Capability | Ecosystem |
|------|------------|-----------|
| **Dependabot** | CVE monitoring + automated PRs | GitHub-hosted; multi-ecosystem |
| **Renovate** | Dependency updates + lockfile maintenance | Self-hosted; multi-ecosystem |
| **OWASP Dependency-Track** | Continuous SBOM analysis + policy enforcement | All ecosystems via SBOM |
| **Socket Security** | Real-time package registry monitoring; ownership change detection | npm, PyPI |
| **OSV-Scanner** | OSV.dev database scanning | Multi-ecosystem; Google-maintained |
| **OpenSSF Scorecard** | Automated security posture scoring | GitHub-hosted projects |
| **Snyk** | CVE + license compliance + reachability | Multi-ecosystem; commercial |

### Monitoring SLAs

| Event | Response SLA |
|-------|-------------|
| Critical CVE in production dependency | Assess within 4 hours; patch or mitigate within 24 hours |
| High CVE in production dependency | Patch or mitigate within 7 days |
| Maintainer account compromise suspected | Audit dependency within 2 hours; pin to last known-good version |
| Ownership transfer detected | Review new owner's history; re-run assessment within 24 hours |
| License change on upgrade | Legal review before upgrading |

---

## Scoring Worksheet

Use this worksheet when conducting a manual or semi-automated assessment.

```
Component Assessment Worksheet
================================
Package name:
Version:
Package registry:
Date of assessment:
Assessor:

DIMENSION SCORES (Healthy = 2 / Caution = 1 / At Risk = 0)
-----------------------------------------------------------
[ ] Maintainer Health: ____
[ ] Security Posture:  ____
[ ] Supply Chain Integrity: ____
[ ] License / Legal: ____
[ ] Community Popularity: ____
[ ] Functionality Scope (inverted): ____

Minimum dimension score: ____
OpenSSF Scorecard score: ____
Known CVEs: ____

RISK TIER (circle one):
  Tier 1 — Approved
  Tier 2 — Conditional
  Tier 3 — Restricted
  Tier 4 — Blocked

DECISION:
  [ ] Approved as-is
  [ ] Approved with compensating controls: __________
  [ ] Blocked — alternative required: __________
  [ ] Escalated to: __________

Approver signature: _________________ Date: __________
```

---

## Exception Management

When a Tier 3 component must be used despite identified risks:

1. **Document the business justification** — why no safer alternative exists
2. **Define compensating controls** — e.g., process isolation, additional SAST rules targeting the component's risk area, additional code review for any code invoking the component
3. **Set an expiry date** — exceptions must be reviewed at least every 90 days
4. **Track in the exception register** — link to the [Compliance Automation Framework exception management process](../../compliance-automation-framework/docs/exception-management.md)

Tier 4 components cannot be approved via exception. They require replacement.

---

## Related Documents

- [SBOM Guide](sbom-guide.md) — SBOM generation and lifecycle management
- [Framework](framework.md) — Software supply chain security controls overview
- [Incident Response Playbook](incident-response-playbook.md) — Responding to supply chain incidents
- [Compliance Automation Framework — Exception Management](../../compliance-automation-framework/docs/exception-management.md)
- [Secure Pipeline Templates — SCA Configuration](../../secure-pipeline-templates/docs/framework.md)
- [OpenSSF Scorecard](https://github.com/ossf/scorecard) — Automated security health scoring
- [OSV.dev](https://osv.dev/) — Open source vulnerability database
- [SLSA Framework](https://slsa.dev/) — Supply chain integrity levels
