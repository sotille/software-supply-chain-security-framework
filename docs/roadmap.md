# Software Supply Chain Security Roadmap

## Table of Contents

- [Roadmap Overview](#roadmap-overview)
- [Month 1–3: Quick Wins and Visibility](#month-13-quick-wins-and-visibility)
- [Month 4–6: SBOM and Signing Foundation](#month-46-sbom-and-signing-foundation)
- [Month 7–9: SLSA Maturity and Policy Enforcement](#month-79-slsa-maturity-and-policy-enforcement)
- [Month 10–12: Advanced Controls and Regulatory Compliance](#month-1012-advanced-controls-and-regulatory-compliance)
- [SLSA Maturity Progression](#slsa-maturity-progression)
- [Regulatory Compliance Milestones](#regulatory-compliance-milestones)
- [Vendor Risk Program Development](#vendor-risk-program-development)
- [Metrics and KPIs](#metrics-and-kpis)

---

## Roadmap Overview

This 12-month roadmap provides a structured path from foundational visibility to advanced supply chain security controls. Each phase builds on the previous, delivering incremental risk reduction while progressing toward regulatory compliance and SLSA maturity targets.

```
Month 1-3: Quick Wins           Month 4-6: SBOM & Signing      Month 7-9: SLSA & Policy       Month 10-12: Advanced
─────────────────────           ──────────────────────────      ──────────────────────          ─────────────────────
● Dependency inventory          ● SBOM generation for all       ● SLSA 2 for all services      ● SLSA 3 for Platinum
● Vulnerability scanning on     ● Artifact signing (Cosign)     ● Admission control (Kyverno)  ● Hermetic builds (pilot)
  all CI pipelines              ● SBOM centralized mgmt         ● Provenance verification       ● VEX workflows
● Private registry deployed     ● License compliance tooling    ● Vendor assessment complete    ● Full EO 14028 compliance
● Dependency pinning > 80%      ● Critical vuln SLA < 7 days    ● SBOM coverage > 95%          ● EU CRA readiness
● Scorecard baselines           ● Signed commit enforcement     ● Unsigned artifact: 0%        ● Runtime monitoring
```

---

## Month 1–3: Quick Wins and Visibility

### Objectives

Establish a comprehensive inventory of the current software supply chain, activate vulnerability scanning across all CI pipelines, and deploy the foundational infrastructure (private registry).

### Month 1: Inventory

**Week 1: Production artifact inventory**

Conduct a complete inventory of all container images and artifacts currently running in production. For each unique image/artifact, record:
- Name and version
- Source repository
- Whether a corresponding SBOM exists
- Whether the artifact is signed
- Last vulnerability scan date and result

```bash
#!/bin/bash
# production-inventory.sh
echo "=== Production Container Inventory ==="
kubectl get pods --all-namespaces -o json | \
  jq -r '.items[].spec.containers[].image' | \
  sort -u | \
  while read image; do
    echo "Image: $image"
    # Check if signed
    cosign verify --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      "$image" 2>/dev/null && echo "  Signed: YES" || echo "  Signed: NO"
    # Check for SBOM attestation
    cosign verify-attestation --type cyclonedx "$image" 2>/dev/null \
      && echo "  SBOM: YES" || echo "  SBOM: NO"
    echo "---"
  done
```

**Week 2: Dependency vulnerability baseline**

Run vulnerability scans across all production artifacts and source repositories. Record baseline metrics:
- Total number of critical vulnerabilities (unmitigated)
- Total number of high vulnerabilities (unmitigated)
- Distribution of vulnerabilities by service tier
- Time since oldest unpatched critical vulnerability was disclosed

**Week 3: Dependency pinning audit**

Audit all production service repositories for dependency pinning compliance:

```bash
# Check Python requirements files for unpinned dependencies
grep -rE "^[a-zA-Z].*[>=<~^]" requirements*.txt --include="*.txt" | \
  grep -v "==" | \
  grep -v "#"

# Check package.json for range dependencies
jq '.dependencies, .devDependencies | to_entries[] | select(.value | test("^[\\^~>]")) | "\(.key): \(.value)"' package.json
```

**Week 4: Private registry deployment**

Deploy Harbor (or equivalent) as the organization's private artifact registry. Begin routing all CI builds to push to the private registry.

### Month 2: Scanning Activation

**All CI pipelines: add vulnerability scanning**

Deploy a standard CI security scanning template that all teams can include in their pipelines:

```yaml
# security-scan.yml (reusable workflow)
name: Supply Chain Security Scan

on:
  workflow_call:
    inputs:
      image-ref:
        required: false
        type: string

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11

      - name: Dependency vulnerability scan (filesystem)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          format: sarif
          output: trivy-fs.sarif
          severity: CRITICAL,HIGH

      - name: Secret scanning
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: HEAD~1
          only-verified: true

      - name: Upload results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-fs.sarif
```

**OpenSSF Scorecard baseline**

Run OpenSSF Scorecard on all production service repositories and record scores. Use scores to prioritize source security improvements:
- Score < 4.0: Immediate remediation (branch protection, signed releases)
- Score 4.0–6.9: Improvement plan within 90 days
- Score >= 7.0: Monitor; maintain

### Month 3: Policy and Process

**Dependency pinning enforcement**

Configure Renovate Bot on all repositories. Enforce that no PR merges without lockfile update if dependencies have changed.

**Critical vulnerability SLA activation**

Publish the vulnerability remediation SLA (Critical: 7 days, High: 30 days). Begin tracking compliance. Create automated JIRA/GitHub Issues for newly discovered critical vulnerabilities.

**Month 1–3 Key Results:**

| Metric | Baseline | Month 3 Target |
|---|---|---|
| Production services with CI vulnerability scanning | 0% | 100% |
| Dependency pinning compliance | Measured | > 80% |
| Critical vulnerabilities (unmitigated) | Measured | Decreasing trend |
| Private registry adoption | 0% | > 50% builds |
| OpenSSF Scorecard (average) | Measured | Baseline established |

---

## Month 4–6: SBOM and Signing Foundation

### Objectives

Achieve universal SBOM generation and artifact signing for all production services. Deploy SBOM centralized management. Enforce signed commits.

### Month 4: SBOM Generation

**SBOM generation in all CI pipelines**

Extend the standard security scanning workflow to include Syft-based SBOM generation:

```yaml
      - name: Generate SBOM
        run: |
          syft ${{ inputs.image-ref }} \
            -o cyclonedx-json=sbom.json \
            -o spdx-json=sbom.spdx.json
          COMPONENT_COUNT=$(jq '.components | length' sbom.json)
          echo "SBOM generated: $COMPONENT_COUNT components"
          echo "sbom-component-count=$COMPONENT_COUNT" >> $GITHUB_OUTPUT

      - name: Validate SBOM completeness
        run: |
          COMPONENTS=$(jq '.components | length' sbom.json)
          if [ "$COMPONENTS" -lt 10 ]; then
            echo "WARNING: SBOM contains only $COMPONENTS components — possible generation failure"
            exit 1
          fi
```

**Dependency-Track deployment**

Deploy Dependency-Track for centralized SBOM management. Configure automated SBOM ingestion from CI pipelines. Set up policy alerts for critical vulnerabilities.

### Month 5: Artifact Signing

**Cosign signing integration**

Integrate Cosign signing into all production CI pipelines using keyless signing:

```yaml
      - name: Install Cosign
        uses: sigstore/cosign-installer@59acb6260d9c0ba8f4a2f9d9b48431a222b68e20  # v3.5.0

      - name: Sign artifact and attest SBOM
        run: |
          # Sign the container image
          cosign sign --yes ${{ env.IMAGE_REF }}@${{ env.IMAGE_DIGEST }}

          # Attest the SBOM
          cosign attest --yes \
            --predicate sbom.json \
            --type cyclonedx \
            ${{ env.IMAGE_REF }}@${{ env.IMAGE_DIGEST }}
```

**Signed commit enforcement**

Enable signed commit requirements on all protected branches for all production service repositories.

### Month 6: Maturation

**License compliance activation**

Integrate FOSSA or equivalent license compliance tooling into CI. Resolve all license policy violations identified during scanning.

**SBOM accuracy validation**

For the 20 highest-criticality services, independently validate SBOM completeness by comparing Syft output with Trivy filesystem scan output. Resolve discrepancies.

**Month 4–6 Key Results:**

| Metric | Month 3 Baseline | Month 6 Target |
|---|---|---|
| Services with SBOM generation in CI | 0% | 100% |
| SBOM attached to artifacts | 0% | 100% |
| Artifacts signed with Cosign | 0% | 100% |
| SBOM centralized management coverage | 0% | 100% |
| Signed commits enforced | 0 repos | All production repos |
| Critical vulnerability SLA compliance | Baseline | > 90% |

---

## Month 7–9: SLSA Maturity and Policy Enforcement

### Objectives

Achieve SLSA Level 2 for all services, SLSA Level 3 for Platinum and Gold tier services. Deploy admission control policies in production.

### Month 7: SLSA Level 2 Rollout

**SLSA provenance generation**

Integrate SLSA provenance generation into all CI pipelines using the SLSA GitHub Generator or Tekton Chains:

```yaml
  slsa-provenance:
    needs: build
    permissions:
      actions: read
      id-token: write
      packages: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
    with:
      image: ${{ needs.build.outputs.image }}
      digest: ${{ needs.build.outputs.digest }}
```

### Month 8: Admission Control Deployment

**Kyverno policy deployment**

Deploy Kyverno policies in audit mode (log violations without blocking) for two weeks, then transition to enforce mode:

```bash
# Deploy Kyverno
helm install kyverno kyverno/kyverno --namespace kyverno --create-namespace

# Apply policies in audit mode first
kubectl apply -f policies/supply-chain-baseline.yaml
# Validate: monitor kyverno-policy-report for violations

# After 2-week validation: switch to enforce mode
kubectl patch clusterpolicy supply-chain-security-policy \
  -p '{"spec":{"validationFailureAction":"Enforce"}}' \
  --type=merge
```

**Provenance verification activation**

Add provenance verification to the admission controller policy for Platinum tier services. Monitor for false positives over a two-week period.

### Month 9: Vendor Assessment Program

**Third-party vendor assessment**

Complete security assessments for all Critical-tier third-party software vendors. For Important-tier vendors, complete questionnaire phase. Establish annual assessment cadence.

**Month 7–9 Key Results:**

| Metric | Month 6 Baseline | Month 9 Target |
|---|---|---|
| SLSA Level 2 compliance | 0% | 100% of production services |
| SLSA Level 3 compliance (Platinum/Gold) | 0% | 80% of Platinum services |
| Admission control active | No | Yes (enforce mode, production) |
| Unsigned artifacts in production | Measured | 0% |
| Critical vendor assessments complete | 0% | 100% |
| SBOM coverage (component coverage) | Measured | > 95% |

---

## Month 10–12: Advanced Controls and Regulatory Compliance

### Objectives

Achieve full EO 14028 compliance, progress toward EU CRA readiness, implement hermetic builds for critical services, and deploy runtime monitoring.

### Month 10: Regulatory Compliance Finalization

**EO 14028 compliance package**

Compile and validate the EO 14028 compliance evidence package for government-facing software:

| EO 14028 Requirement | Evidence | Status |
|---|---|---|
| SBOM provision | SBOM generation in CI + Dependency-Track inventory | Month 4 complete |
| Artifact signing | Cosign signatures on all production images | Month 5 complete |
| MFA for all developers | IdP MFA enforcement audit | Month 10 action |
| SSDF compliance | Gap assessment vs. NIST SP 800-218 | Month 10 action |
| EDR deployment | EDR coverage audit | Month 10 action |
| Encryption in transit and at rest | Audit and evidence package | Month 10 action |

### Month 11: Advanced Build Security

**Hermetic build pilot (Platinum services)**

Implement hermetic builds for the two highest-criticality Platinum-tier services using Bazel or a containerized hermetic build approach:

```dockerfile
# hermetic-build.Dockerfile
# All dependencies pre-fetched before build
FROM build-deps:1.0.0 AS dependency-cache
# This image contains all resolved dependencies, built separately and pinned by digest
# No network access available during the actual build stage

FROM dependency-cache AS builder
COPY --network=none . /src
WORKDIR /src
RUN --network=none mvn package -DskipTests
# --network=none enforces hermetic isolation: no outbound network during build
```

**VEX workflow implementation**

Implement VEX statement generation for vulnerabilities that affect components in your software but are not exploitable in your specific usage:

```bash
# Generate VEX document for a known non-exploitable CVE
cyclonedx-cli vex create \
  --sbom payment-service.cdx.json \
  --vulnerability CVE-2023-12345 \
  --state not_affected \
  --justification code_not_reachable \
  --detail "The vulnerable XML parsing code path is only invoked when external entity processing is enabled. Our configuration disables external entity processing." \
  --output payment-service-vex.json
```

### Month 12: Runtime Monitoring and Continuous Improvement

**Falco deployment for runtime integrity**

```yaml
# falco-supply-chain-rules.yaml
- rule: Unexpected Outbound Network from Build Container
  desc: Detect unexpected outbound connections from build containers (possible hermetic build violation)
  condition: >
    spawned_process and
    container.image.repository contains "build" and
    fd.typechar = 4 and
    fd.is_server = false
  output: >
    Unexpected network from build container
    (user=%user.name image=%container.image.repository
    dest=%fd.rip:%fd.rport)
  priority: WARNING
  tags: [supply_chain, build_integrity]

- rule: Binary Execution in Production Container from Unexpected Path
  desc: Detect execution of binaries from unexpected paths (possible supply chain compromise)
  condition: >
    spawned_process and
    container.name != "" and
    not proc.exepath startswith "/usr/local/bin" and
    not proc.exepath startswith "/app" and
    not proc.exepath startswith "/usr/bin" and
    proc.exepath != "<NA>"
  output: >
    Unexpected binary executed in container
    (user=%user.name image=%container.image.repository
    exe=%proc.exepath cmdline=%proc.cmdline)
  priority: HIGH
  tags: [supply_chain, runtime_integrity]
```

---

## SLSA Maturity Progression

### Current State to Target State

| Service Tier | Count (example) | Month 0 | Month 6 | Month 9 | Month 12 |
|---|---|---|---|---|---|
| Platinum | 5 | 0 | 1 | 3 | 5 |
| Gold | 15 | 0 | 2 | 8 | 15 |
| Silver | 40 | 0 | 0 | 2 | 10 |
| Bronze | 80+ | 0 | 0 | 0 | SLSA 1 only |

*Numbers represent SLSA Level 3 adoption. All services reach SLSA 1 by month 3, SLSA 2 by month 7.*

### SLSA Level Requirement Checklist

**SLSA Level 1:**
- [ ] Build process documented
- [ ] Provenance generated (need not be signed)
- [ ] Provenance available alongside artifact

**SLSA Level 2:**
- [ ] All Level 1 requirements
- [ ] Hosted build service (GitHub Actions, Cloud Build)
- [ ] Provenance signed by build service
- [ ] Source is version controlled

**SLSA Level 3:**
- [ ] All Level 2 requirements
- [ ] Isolated build environment (ephemeral runners)
- [ ] Non-falsifiable provenance (generated by platform, not pipeline YAML)
- [ ] Provenance verified at consumption
- [ ] Build is auditable (full logs retained)

**SLSA Level 4:**
- [ ] All Level 3 requirements
- [ ] Hermetic build (no network during build)
- [ ] Reproducible build (same inputs → same output)
- [ ] Two-person review on all source changes
- [ ] Internally audited build platform

---

## Regulatory Compliance Milestones

### EO 14028 Compliance (US Federal)

| Requirement | Target Month | Lead Team |
|---|---|---|
| SBOM generation capability | Month 4 | Platform Security |
| SBOM format (CycloneDX or SPDX) | Month 4 | Platform Security |
| Artifact signing | Month 5 | Platform Security |
| Secure development attestation (SSDF) | Month 10 | CISO |
| MFA for all personnel | Month 10 | IT Security |
| Encryption in transit and at rest | Month 10 | IT Security |
| EDR deployment | Month 10 | IT Security |
| Zero trust architecture plan | Month 12 | CISO |

### EU Cyber Resilience Act Readiness

| Requirement | Target Month | Lead Team |
|---|---|---|
| Vulnerability disclosure policy published | Month 3 | Security |
| SBOM generation and provision | Month 4 | Platform Security |
| Vulnerability management program with SLAs | Month 3 | Security |
| Secure development practices documentation | Month 6 | Engineering |
| Incident reporting process | Month 6 | Security |
| Post-market surveillance program | Month 9 | Security |

---

## Vendor Risk Program Development

### Program Maturity Milestones

| Milestone | Month | Deliverable |
|---|---|---|
| Vendor inventory complete | 2 | Complete list of all third-party software vendors with tier classification |
| Assessment questionnaire finalized | 3 | Standardized supply chain security assessment questionnaire |
| Critical vendor assessments complete | 9 | Assessment results for all Critical-tier vendors |
| Important vendor assessments complete | 12 | Assessment results for all Important-tier vendors |
| Remediation SLA established | 6 | Published SLA for vendor security issue remediation |
| Contract clauses updated | 9 | Updated vendor contracts with supply chain security obligations |
| Continuous monitoring active | 12 | Automated CVE alerting for all Critical vendor software |

### Vendor Contract Requirements

Add the following clauses to new and renewed vendor contracts for Critical and Important tier software:

- SBOM provision for all covered software, updated within 30 days of any new release
- Notification within 24 hours of any confirmed supply chain compromise or critical vulnerability affecting covered software
- Annual security assessment cooperation (provide responses to questionnaire within 30 business days)
- Code signing requirement for all software releases
- Right to audit supply chain security practices with 30 days notice

---

## Metrics and KPIs

### Primary Security Metrics

| KPI | Description | Month 3 Target | Month 6 Target | Month 12 Target |
|---|---|---|---|---|
| **Vulnerability discovery time** | Time from CVE publication to organizational awareness for components in use | < 24 hours | < 4 hours (automated) | < 1 hour (automated) |
| **Vulnerability remediation time (Critical)** | Time from discovery to deployed patch (Critical CVEs) | < 14 days | < 7 days | < 5 days |
| **SBOM coverage** | % of production artifacts with a complete, current SBOM | 0% | 100% | 100% |
| **Unsigned artifact percentage** | % of production artifacts without a valid cryptographic signature | Measured | < 10% | 0% |
| **Dependency pinning rate** | % of production services with all dependencies pinned to exact versions | Measured | > 90% | 100% |
| **SLSA Level 2+ compliance** | % of production services meeting SLSA Level 2 or higher | 0% | 50% | 100% |
| **Critical vendor assessment completion** | % of Critical-tier vendors with completed supply chain assessment | 0% | 30% | 100% |
| **OpenSSF Scorecard average** | Average OpenSSF Scorecard across all production repositories | Measured | Trending up | > 7.0 |

### Operational Metrics

| KPI | Description | Target |
|---|---|---|
| **New dependency approval time** | Time from request to approval/rejection for new open source dependencies | < 5 business days |
| **False positive rate (signing)** | % of valid artifacts rejected by admission controller signature verification | < 0.1% |
| **Admission control coverage** | % of production namespace Pods subject to signature verification policy | 100% |
| **SBOM ingestion lag** | Delay between artifact publication and SBOM availability in Dependency-Track | < 30 minutes |
| **VEX statements issued** | Number of VEX statements issued (for non-exploitable vulnerabilities) | Trending up (indicates active program) |

### Reporting Cadence

| Audience | Frequency | Content |
|---|---|---|
| CISO / Security Leadership | Monthly | Vulnerability posture, SLSA progress, regulatory compliance status, vendor assessment status |
| Engineering Leadership | Monthly | Unsigned artifact %, SBOM coverage, critical vulnerability SLA compliance, tool adoption |
| All Engineers | Quarterly | Supply chain security program update, new tooling, best practices refresher |
| Board / Audit Committee | Quarterly | Risk posture summary, regulatory readiness, major incidents |
| External Auditors | Annual | Full compliance evidence package, SBOM inventory, assessment records |
