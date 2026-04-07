# Vendor Security Assessment Templates

Third-party vendors — SaaS platforms, open source projects with commercial support, managed services, and infrastructure providers — are a primary attack surface in the software supply chain. Assessing vendor security posture before procurement, at contract renewal, and following security incidents reduces the likelihood of supply chain compromise through trusted third parties.

This document provides structured assessment templates for three vendor categories: SaaS software vendors, open source projects, and critical infrastructure providers.

---

## Assessment Frequency and Trigger Events

| Assessment Type | Frequency | Trigger Events |
|----------------|-----------|---------------|
| **Initial assessment** | Before procurement | N/A |
| **Annual review** | Annually | Contract renewal; material platform changes |
| **Incident-triggered review** | As needed | Vendor breach disclosure; CVE in vendor component; regulatory action against vendor |
| **Material change review** | As needed | Vendor acquisition; change of ownership; new data processing activities |

**Criticality-based frequency:**

| Vendor Criticality | Assessment Frequency | Definition |
|-------------------|---------------------|-----------|
| **Tier 1: Critical** | Annually + incident-triggered | Processes or has access to production systems, sensitive data, or source code |
| **Tier 2: Important** | Every 18 months | Processes internal data; part of CI/CD toolchain |
| **Tier 3: Standard** | Every 2 years | No access to sensitive data; indirect supply chain participant |

---

## Template 1: SaaS Vendor Security Assessment

Use this template for any SaaS product that integrates with your development pipeline, processes sensitive data, or hosts workloads on your behalf.

### Section A: Security Certifications and Audit Reports

| Question | Acceptable Response | Requires Follow-Up |
|----------|--------------------|--------------------|
| Does the vendor hold a current SOC 2 Type II report? | Yes — report within 12 months | No report; Type I only; report > 12 months old |
| Is a copy of the SOC 2 report available under NDA? | Yes | Report available only for enterprise tier customers |
| Does the vendor hold ISO 27001:2022 certification? | Yes — in-scope systems include the product being procured | Certificate expired; earlier version (27001:2013) |
| If handling payment data: PCI DSS Level 1 SAQ or ROC? | Compliant; current attestation | Not assessed; SAQ only (for significant data volumes) |
| If US federal customer: FedRAMP authorization? | JAB P-ATO or Agency ATO at appropriate impact level | FedRAMP In Process (acceptable for procurement with timeline commitment) |
| Are penetration tests conducted annually by an independent third party? | Yes — findings summary available under NDA | No third-party tests; only internal assessments |

**Document requests:**
- [ ] SOC 2 Type II report (current)
- [ ] ISO 27001 certificate (current)
- [ ] Penetration test summary (most recent; findings and remediation status)
- [ ] Vulnerability disclosure policy (VDP) or Bug Bounty program details

### Section B: Data Security and Privacy

| Question | Acceptable Response | Requires Follow-Up |
|----------|--------------------|--------------------|
| What data does the vendor process on our behalf? | Explicit, documented list | "We don't store your data" (vague; unverifiable) |
| Where is data stored (regions and countries)? | Specific regions named; data residency controls available | "In the cloud" (insufficient specificity) |
| Is data encrypted at rest? | AES-256; customer-managed key (BYOK) option | Provider-managed keys only; encryption not confirmed |
| Is data encrypted in transit? | TLS 1.2+ enforced; TLS 1.3 preferred | HTTP option available; older TLS versions supported |
| What is the data retention and deletion policy? | Documented; customer-initiated deletion supported; < 30-day deletion SLA | No deletion capability; unclear retention |
| Does the vendor use subprocessors for our data? | Yes — subprocessor list maintained and notified on change | Subprocessors not disclosed |
| Is a Data Processing Agreement (DPA) available? | Yes — GDPR-compliant DPA with SCCs for international transfers | DPA not available; refusal to sign |

### Section C: Access and Identity Controls

| Question | Acceptable Response | Requires Follow-Up |
|----------|--------------------|--------------------|
| Is MFA enforced for all accounts with access to our data? | Mandatory MFA; TOTP or hardware key supported | MFA optional; SMS-only MFA |
| Does the vendor support SAML 2.0 or OIDC SSO? | Yes — SSO supported; enforcement option for enterprise | SSO available only on highest pricing tier |
| How are vendor employees with system access provisioned/deprovisioned? | Automated provisioning/deprovisioning on HR system events | Manual offboarding; no SLA for access removal |
| What access logs are available to the customer? | Customer-accessible audit logs for data access events | No access logs; logs available only by request |
| Are privileged access activities logged and reviewed? | PAM solution in use; quarterly access reviews | No privileged access controls documented |

### Section D: Vulnerability Management

| Question | Acceptable Response | Requires Follow-Up |
|----------|--------------------|--------------------|
| How does the vendor disclose security vulnerabilities? | Security advisory mailing list or RSS; CVE numbering authority (CNA) registered | No disclosure mechanism; no CVE process |
| What are the vendor's SLAs for critical vulnerability patching? | Critical: 7 days; High: 30 days | SLAs not published; "we patch when we can" |
| Does the vendor generate SBOMs for their software? | CycloneDX or SPDX SBOM available; EO 14028 compliant | No SBOM; unknown dependencies |
| Is the vendor on the CISA KEV list or subject to active exploitation? | Check: [cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Active KEV entry for vendor's software |

### Section E: Incident Response

| Question | Acceptable Response | Requires Follow-Up |
|----------|--------------------|--------------------|
| What are the vendor's breach notification SLAs? | Notification within 72 hours of becoming aware (GDPR standard) | Notification only after investigation complete (could be weeks) |
| Does the vendor have a documented IR plan? | Yes — summary available; annual tabletop exercise conducted | No documented IR plan |
| Has the vendor experienced a breach in the last 3 years? | Disclose with details; demonstrate lessons learned | Refusal to disclose; vague answer |
| Is security incident history tracked in public disclosure? | Searchable via CVE database and vendor security advisory page | No public disclosure history |

### Scoring and Decision Framework

Score each section 1–5:
- **5:** Full compliance; best practice; verifiable evidence
- **3:** Adequate; some gaps; acceptable with monitoring
- **1:** Major gap; compliance failure; unacceptable risk

| Section | Weight | Minimum Acceptable Score |
|---------|--------|-------------------------|
| A: Certifications | 25% | 3.0 |
| B: Data security | 30% | 3.5 |
| C: Access controls | 20% | 3.0 |
| D: Vulnerability management | 15% | 3.0 |
| E: Incident response | 10% | 3.0 |

**Weighted score < 3.0:** Do not proceed. Escalate to CISO.
**Weighted score 3.0–3.9:** Conditional approval with documented risk exceptions and remediation commitments.
**Weighted score ≥ 4.0:** Approved. Document findings. Schedule annual review.

---

## Template 2: Open Source Project Assessment

Use this template before introducing a new open source dependency as a critical component — in your application, CI/CD toolchain, or infrastructure.

**Scope:** Apply this assessment to dependencies that are:
- Direct dependencies with privileged access (CI/CD plugins, authentication libraries, cryptographic libraries)
- Infrastructure-level dependencies (container base images, OS packages in published images)
- Components that process sensitive data

Transitive dependencies are out of scope for this assessment but are covered by automated SCA scanning.

### Section A: Project Health and Governance

| Criterion | Green | Yellow | Red |
|-----------|-------|--------|-----|
| **Maintainer activity** | Commits within 30 days | Commits within 90 days | No commits in 90+ days |
| **Issue response time** | Open issues addressed within 30 days | Issues addressed within 90 days | Many stale issues; no response to CVE reports |
| **Release frequency** | Regular releases with changelogs | Releases exist; irregular | Last release > 12 months ago |
| **Maintainer count** | ≥ 3 active maintainers | 2 active maintainers | Single maintainer (bus factor 1) |
| **Organizational backing** | CNCF, Apache, Linux Foundation, or company-backed | Community project with sponsorship | Solo project; no organizational support |
| **Security policy** | SECURITY.md present; CVE process documented | Contact email present | No security contact; no disclosure process |
| **Dependency count** | ≤ 5 direct dependencies | 6–15 direct dependencies | > 15 direct dependencies |

### Section B: Security Track Record

| Criterion | Assessment |
|-----------|-----------|
| **CVE history** | Search NVD (nvd.nist.gov) for CVEs against this package. Multiple critical CVEs in past 2 years is a risk signal. |
| **Active exploitation** | Check CISA KEV and GitHub security advisories for known exploitation. |
| **Time to patch historical CVEs** | High-quality projects patch critical CVEs within 7 days. Examine recent CVE publication → fix commit timeline. |
| **Supply chain hygiene** | Is the package signed? Published via trusted registries (PyPI, npm, Maven Central) with provenance? |
| **Dependency pinning** | Does the project pin its own dependencies to exact versions or digests? Floating dependencies are a risk multiplier. |

### Section C: Supply Chain Risk

| Risk Factor | How to Assess |
|-------------|--------------|
| **Typosquatting** | Is the package name a common typosquatting target? (e.g., `django` vs `djago`). Check npm/PyPI for similar-named packages with different publishers. |
| **Publisher verification** | Is the publisher the expected organization? Verify the publishing account matches the project's primary maintainer, not a fork. |
| **Recent ownership changes** | Check npm/PyPI ownership transfer history. Recent transfers to unknown accounts are a high-risk signal. |
| **Install scripts** | Does the package run install scripts (`preinstall`, `postinstall` in npm; `setup.py` in Python)? These execute during `npm install` or `pip install` with no further prompt. |
| **Minimal surface area** | Does the package request more system access than its function requires? |

**Assessment for critical dependencies:**

```bash
# npm package audit — check supply chain signals
npx npm-audit-resolver    # Interactive audit with resolution options

# Check for install scripts
cat node_modules/package-name/package.json | jq '.scripts | keys'

# Verify publisher on npm registry
npm info package-name maintainers

# Check package signing (npm provenance)
npm info package-name --json | jq '.dist.signatures'
```

### Section D: License Compatibility

| License Category | Examples | Action |
|-----------------|---------|--------|
| **Permissive** | MIT, Apache 2.0, BSD-2/3 | Approved for commercial use |
| **Weak copyleft** | LGPL, MPL 2.0 | Approved with dynamic linking; review static linking |
| **Strong copyleft** | GPL v2, GPL v3, AGPL | Requires legal review before use in commercial products |
| **Unknown / custom** | No SPDX identifier; custom license text | Block until legal review completed |

```bash
# License audit with FOSSA or license-checker
npx license-checker --summary --excludePackages "your-app@1.0.0"
```

---

## Template 3: Critical Infrastructure Provider Assessment

Use this template for cloud providers, CDN providers, DNS providers, and managed infrastructure services that form the operational foundation of your systems.

### Section A: Service Reliability and Security Commitments

| Topic | Questions | Evidence Required |
|-------|-----------|-----------------|
| **SLA and uptime** | What is the contractual SLA? What compensation is offered for breach? | SLA documentation; recent uptime history |
| **Security certifications** | SOC 2 Type II? ISO 27001? ISO 27017/27018 (cloud)? FedRAMP (if applicable)? | Current certification documents |
| **Shared responsibility model** | What security is the provider's responsibility vs. the customer's? | Documented shared responsibility matrix |
| **Data residency options** | Can data be pinned to specific regions? Are cross-region transfers auditable? | Region configuration documentation |

### Section B: Incident and Breach History

| Criterion | How to Assess |
|-----------|--------------|
| **Public incident history** | Review the provider's status page history. Major providers maintain incident histories at status.provider.com. Evaluate frequency and resolution time. |
| **Breach disclosure** | Search public records for data breaches involving the provider. Note if customer data was involved and how the provider responded. |
| **Regulatory actions** | Have regulators (FTC, ICO, CNIL) taken action against the provider? Regulatory action is a leading indicator of systemic security failures. |

### Section C: Access and Credential Management

| Control | What to Verify |
|---------|--------------|
| **Account isolation** | Does the provider offer account-level isolation (AWS Organizations, GCP Projects, Azure Subscriptions)? |
| **Workload identity** | Does the provider support OIDC federation for CI/CD pipeline authentication? (Eliminates long-lived credentials) |
| **Access log completeness** | Are all API calls logged with actor identity, timestamp, resource, and action? Are logs tamper-evident? |
| **Key management** | Does the provider offer customer-managed encryption keys (CMEK/BYOK)? |

---

## Vendor Risk Register Integration

Assessment results feed into the organizational vendor risk register. Each vendor's entry should include:

```yaml
vendor:
  name: "Example SaaS Co."
  tier: 1
  data_classification: "confidential"
  assessment_date: "2026-01-15"
  next_assessment_due: "2027-01-15"
  assessor: "security-team@example.com"

  scores:
    certifications: 4.5
    data_security: 4.0
    access_controls: 3.5
    vulnerability_management: 3.0
    incident_response: 4.0
    weighted_total: 3.85

  status: "approved_with_conditions"

  conditions:
    - "Vendor must provide 72-hour breach notification per DPA terms"
    - "Annual SOC 2 report must be provided before contract renewal"

  risk_exceptions:
    - id: "VRE-2026-001"
      description: "Vendor does not support BYOK; using provider-managed keys for non-production data only"
      owner: "CISO"
      expiry: "2026-12-31"
      compensating_controls:
        - "Additional access logging enabled"
        - "Data limited to non-production and anonymized datasets"
```

---

## Cross-References

| Topic | Document |
|-------|---------|
| Open source component assessment (detailed) | [Open Source Component Assessment](open-source-component-assessment.md) |
| SBOM verification for vendor components | [SBOM Guide](sbom-guide.md) |
| Incident response for supply chain attacks | [Incident Response Playbook](incident-response-playbook.md) |
| Compliance controls for vendor management | [Compliance Automation Framework — Governance](../../compliance-automation-framework/docs/framework.md) |
| FedRAMP vendor assessment requirements | [FedRAMP Implementation Guide](../../compliance-automation-framework/docs/fedramp-implementation-guide.md) |
