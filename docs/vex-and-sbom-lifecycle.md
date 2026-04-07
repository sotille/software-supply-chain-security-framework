# VEX Workflow and SBOM Lifecycle Management

This document covers two essential but frequently absent practices in software supply chain security programs:

1. **VEX (Vulnerability Exploitability eXchange)** — how to communicate whether a known CVE in an SBOM component actually affects your software, and how to operationalize VEX to reduce false positives and automate vulnerability disposition.
2. **SBOM Lifecycle Management** — how to keep SBOMs accurate over the life of a software artifact, manage versions, and meet archival requirements for compliance and audit.

Both topics are prerequisites for a mature supply chain security program. Generating SBOMs without a lifecycle strategy produces stale, unreliable data. Publishing vulnerability findings without VEX context produces noise that undermines response prioritization.

---

## Part 1: VEX Workflow

### What VEX Is

A VEX document is an assertion by a software producer about whether a specific vulnerability (identified by CVE or GHSA) in a component affects a specific product version. VEX answers the question: "We know this CVE exists in a library we use. Does that CVE affect us?"

VEX has four possible assessments for each CVE/product combination:

| VEX Status | Meaning | Downstream Action |
|------------|---------|-------------------|
| **Affected** | The vulnerability is present and exploitable in this product | Treat as a real finding; apply patch or workaround |
| **Not Affected** | The vulnerability exists in a dependency but cannot be exploited in this product | Suppress the finding in vulnerability scanners |
| **Fixed** | The vulnerability was present in an earlier version and has been remediated | Close the finding; link to the fix commit or release |
| **Under Investigation** | Assessment is in progress | Hold the finding; do not suppress until investigation completes |

### Why VEX Matters

Without VEX, vulnerability scanners report every CVE in every dependency — including vulnerabilities in code paths your application never calls, in functions protected by compensating controls, or in optional features your build excludes. The practical effect is:

- Developers spend hours triaging CVEs that do not affect them.
- Security teams lose credibility when they report findings that engineering can immediately identify as irrelevant.
- Automated gates block deployments on non-exploitable findings.
- Regulated environments require "risk accepted" evidence for non-exploitable CVEs, creating manual compliance overhead.

VEX transforms vulnerability data from a raw list into a risk-qualified view.

---

### VEX Document Formats

Two formats are in active use:

**CycloneDX VEX (preferred for DevSecOps pipelines)**

CycloneDX treats VEX as a first-class concept. VEX data can be embedded in the SBOM itself or published as a standalone CycloneDX VEX document.

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2024-03-15T10:00:00Z",
    "component": {
      "type": "application",
      "name": "payment-service",
      "version": "3.2.1",
      "purl": "pkg:docker/myregistry.io/payment-service@sha256:a3f8c7d9..."
    }
  },
  "vulnerabilities": [
    {
      "id": "CVE-2021-44228",
      "source": {
        "name": "NVD",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
      },
      "ratings": [
        {
          "source": { "name": "NVD" },
          "score": 10.0,
          "severity": "critical",
          "method": "CVSSv31"
        }
      ],
      "affects": [
        {
          "ref": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
          "versions": [
            {
              "version": "2.14.1",
              "status": "not_affected"
            }
          ]
        }
      ],
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "payment-service uses log4j-core 2.14.1 in the dependency graph, but does not use JNDI lookup or any JNDI-related log4j features. The vulnerable code path is not callable in any execution context of this service. Verified by static analysis and code review on 2024-03-15.",
        "responses": ["will_not_fix"],
        "firstIssued": "2024-03-15T10:00:00Z",
        "lastUpdated": "2024-03-15T10:00:00Z"
      }
    }
  ]
}
```

**OpenVEX (CISA-led format)**

OpenVEX is a minimal, JSON-LD based format designed for standalone VEX documents, especially in open source ecosystems.

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/payment-service-v3.2.1-cve-2021-44228",
  "author": "Techstream Security Team <security@example.com>",
  "timestamp": "2024-03-15T10:00:00Z",
  "last_updated": "2024-03-15T10:00:00Z",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "@id": "https://www.cve.org/CVERecord?id=CVE-2021-44228",
        "name": "CVE-2021-44228"
      },
      "products": [
        {
          "@id": "pkg:docker/myregistry.io/payment-service@sha256:a3f8c7d9..."
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "JNDI lookup is not invoked in this service. The application does not configure or call log4j JNDI appenders."
    }
  ]
}
```

**Format selection guidance:**
- Use **CycloneDX VEX** when your toolchain uses Dependency-Track, Grype, or other CycloneDX-native tools.
- Use **OpenVEX** when distributing VEX alongside open source packages or when CISA/government alignment is a requirement.
- Both formats can be signed with Cosign and attached as in-toto attestations.

---

### VEX Justification Values

The CycloneDX VEX specification defines the following `justification` values for `not_affected` status:

| Justification | When to Use |
|---------------|------------|
| `component_not_present` | The component containing the CVE is listed as a transitive dependency but is not actually included in the final artifact (tree-shaking, optional dependency). |
| `vulnerable_code_not_present` | The vulnerable function or class exists in the dependency but was excluded at build time (stripped binary, conditional compile). |
| `vulnerable_code_not_in_execute_path` | The vulnerable code is present but is never called by any execution path in this application. Requires code analysis evidence. |
| `vulnerable_code_cannot_be_controlled_by_adversary` | The vulnerable code path can be reached but requires attacker-controlled input that is sanitized or validated before reaching it. |
| `inline_mitigations_already_exist` | The application applies compensating controls (e.g., WAF rules, input validation) that prevent exploitation of the vulnerability in this context. |

**Important:** Justifications other than `component_not_present` and `vulnerable_code_not_present` require documented evidence. Assertions like "the code cannot be reached" without static analysis or code review evidence are not auditor-acceptable.

---

### Operationalizing VEX in a CI/CD Pipeline

#### Step 1: Generate SBOM and initial vulnerability scan

```yaml
# GitHub Actions — SBOM generation and vulnerability scan
- name: Generate SBOM
  run: |
    syft scan ${{ env.IMAGE_DIGEST }} -o cyclonedx-json=sbom.cdx.json

- name: Vulnerability scan against SBOM
  run: |
    grype sbom:./sbom.cdx.json \
      --output json \
      --file grype-results.json \
      --fail-on critical
```

#### Step 2: Apply VEX to suppress known non-exploitable findings

```bash
# Using vexctl (OpenVEX tooling) to apply a VEX document to Grype results
vexctl filter \
  --vex ./vex/payment-service-v3.2.1.vex.json \
  --products "pkg:docker/myregistry.io/payment-service@sha256:..." \
  grype-results.json > filtered-results.json

# The filtered results contain only findings where VEX status is "affected"
# or "under_investigation" — not_affected and fixed are suppressed
```

#### Step 3: Attach VEX as a Cosign attestation

```bash
# Attach the VEX document to the container image as a Cosign attestation
cosign attest \
  --predicate ./vex/payment-service-v3.2.1.vex.json \
  --type openvex \
  ${{ env.IMAGE_DIGEST }}

# Verification at promotion gate:
cosign verify-attestation \
  --type openvex \
  --certificate-identity-regexp "^https://github.com/<org>/<repo>/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ${{ env.IMAGE_DIGEST }} \
  | jq '.payload | @base64d | fromjson | .statements'
```

#### Step 4: Policy gate using VEX-filtered results

```yaml
- name: Fail pipeline on VEX-adjusted critical findings
  run: |
    CRITICAL_COUNT=$(jq '[.matches[] | select(.vulnerability.severity == "CRITICAL")] | length' filtered-results.json)
    if [ "$CRITICAL_COUNT" -gt 0 ]; then
      echo "FAIL: ${CRITICAL_COUNT} exploitable CRITICAL vulnerabilities after VEX filtering"
      jq '.matches[] | select(.vulnerability.severity == "CRITICAL") | {cve: .vulnerability.id, component: .artifact.name, version: .artifact.version}' filtered-results.json
      exit 1
    fi
    echo "PASS: 0 exploitable CRITICAL vulnerabilities after VEX filtering"
```

---

### VEX Governance

VEX assertions are security claims. They require governance to prevent misuse (e.g., incorrectly marking a real vulnerability as "not affected" to pass a pipeline gate).

**Approval requirements by justification type:**

| VEX Assertion Type | Minimum Required Approval |
|-------------------|--------------------------|
| `component_not_present` | Automated (verifiable by SBOM tooling) |
| `vulnerable_code_not_present` | Security engineer sign-off |
| `vulnerable_code_not_in_execute_path` | Security engineer sign-off + static analysis evidence |
| `vulnerable_code_cannot_be_controlled_by_adversary` | Security engineer + Application Architect sign-off |
| `inline_mitigations_already_exist` | Security engineer + Application Security review |

**VEX review cadence:**

| CVE Severity | Review Frequency |
|-------------|-----------------|
| Critical | Review every 30 days; re-verify if application changes touch affected code paths |
| High | Review every 90 days |
| Medium | Review every 180 days |
| All statuses | Re-evaluate whenever the affected component is upgraded |

**VEX inventory:** Maintain a VEX registry — a tracked store of all VEX assertions, their approval status, assigned owner, expiry date, and the evidence supporting the assertion. This registry is audit evidence for vulnerability management controls.

---

### VEX Staleness Detection and Expiration Workflows

A `not_affected` VEX assertion that was correct at time of issue may become incorrect as the codebase evolves. Refactoring can introduce previously absent code paths; new features may call library functions that were previously unreachable. VEX assertions must be treated as perishable claims — not permanent suppressions.

**When a VEX assertion can become stale:**

| Change Type | Risk of VEX Staleness | Detection Method |
|-------------|----------------------|------------------|
| Component upgrade (affected library) | High — new version may behave differently | Trigger VEX re-review on every upgrade of the affected package |
| Refactoring in consuming service | Medium — newly added code paths may reach vulnerable functions | SAST/call-graph analysis re-run on every PR that touches files adjacent to the affected component |
| Dependency tree change (new transitive dependency) | Low–Medium | Re-run SBOM generation; compare dependency tree against prior VEX assertions |
| Base image update | Medium for `component_not_present` assertions | Re-validate component presence after image rebuild |
| New CVE assigned to same component (different issue) | Low but confusing | Require separate VEX per CVE identifier — do not extend existing assertions |

**Automated staleness detection pipeline:**

```yaml
# GitHub Actions — VEX staleness check on every PR
name: VEX Staleness Review

on:
  pull_request:
    branches: [main]

jobs:
  vex-staleness-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Detect dependency changes
        id: dep-changes
        run: |
          # Check if any dependency manifest changed in this PR
          CHANGED=$(git diff --name-only origin/${{ github.base_ref }}...HEAD \
            | grep -E 'package\.json|go\.mod|requirements\.txt|pom\.xml|Gemfile|Cargo\.toml|go\.sum' \
            || true)
          echo "changed_deps=${CHANGED}" >> $GITHUB_OUTPUT
          if [ -n "$CHANGED" ]; then
            echo "dependency_files_changed=true" >> $GITHUB_OUTPUT
          fi

      - name: Flag VEX assertions for review if deps changed
        if: steps.dep-changes.outputs.dependency_files_changed == 'true'
        run: |
          # List all active VEX assertions that reference changed dependency scope
          echo "Dependency changes detected in this PR. The following VEX assertions may require re-review:"
          echo ""
          # Parse VEX registry for assertions with 'not_affected' or 'under_investigation' status
          jq -r '.assertions[] | select(.status == "not_affected" or .status == "under_investigation") |
            "  CVE: \(.cve_id) | Component: \(.component) | Justification: \(.justification) | Owner: \(.owner) | Expires: \(.expiry_date)"' \
            ./vex-registry/vex-inventory.json || echo "  No active VEX registry found — run initial VEX inventory."

          echo ""
          echo "ACTION REQUIRED: Review the above assertions and confirm they remain valid."
          echo "Update expiry dates in vex-registry/vex-inventory.json if assertions remain correct."
          echo "Create new VEX documents for any assertions that require re-evaluation."
```

**VEX expiration enforcement:**

```python
#!/usr/bin/env python3
# vex-expiry-check.py — Run daily in CI to flag expired VEX assertions
import json
import sys
from datetime import datetime, date

VEX_REGISTRY = "vex-registry/vex-inventory.json"
TODAY = date.today()
WARN_DAYS = 14  # Warn when within 14 days of expiry

with open(VEX_REGISTRY) as f:
    registry = json.load(f)

expired = []
expiring_soon = []

for assertion in registry.get("assertions", []):
    expiry = date.fromisoformat(assertion["expiry_date"])
    days_remaining = (expiry - TODAY).days

    if days_remaining < 0:
        expired.append((assertion, days_remaining))
    elif days_remaining <= WARN_DAYS:
        expiring_soon.append((assertion, days_remaining))

if expired:
    print(f"ERROR: {len(expired)} EXPIRED VEX assertion(s) — these must be re-reviewed immediately:")
    for a, d in expired:
        print(f"  {a['cve_id']} / {a['component']} — expired {abs(d)} days ago — owner: {a['owner']}")

if expiring_soon:
    print(f"WARNING: {len(expiring_soon)} VEX assertion(s) expiring within {WARN_DAYS} days:")
    for a, d in expiring_soon:
        print(f"  {a['cve_id']} / {a['component']} — expires in {d} days — owner: {a['owner']}")

if expired:
    sys.exit(1)  # Fail CI if expired assertions are present
```

**VEX inventory schema** (store as `vex-registry/vex-inventory.json`):

```json
{
  "last_updated": "2024-03-15",
  "assertions": [
    {
      "cve_id": "CVE-2021-44228",
      "component": "org.apache.logging.log4j:log4j-core",
      "component_version": "2.14.1",
      "affected_service": "payment-service",
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "evidence_reference": "docs/vex-evidence/CVE-2021-44228-payment-service.md",
      "approved_by": "security-engineer@example.com",
      "approval_date": "2024-03-15",
      "expiry_date": "2024-06-15",
      "review_trigger": "any upgrade of log4j-core",
      "owner": "platform-security@example.com"
    }
  ]
}
```

---

### Handling Zero-Day and Unknown CVEs

Not all vulnerability findings arrive via an assigned CVE identifier. Supply chain security programs must handle three categories of unassigned or ambiguous vulnerability signals:

**Category 1: CVE reserved but not yet populated (NVD lag)**

The NVD regularly delays publication of CVE details by days to weeks after initial disclosure. During this window, scanners may report a CVE ID with no CVSS score, no description, and no affected version ranges.

| Handling | Procedure |
|----------|-----------|
| **Do not suppress** | A CVE with no NVD details cannot be VEX-assessed. Hold as `under_investigation`. |
| **Set SLA timer** | For Critical/High severity vendors (e.g., directly disclosed by a major vendor), apply a 7-day investigation SLA regardless of NVD publication status. |
| **Monitor the CVE** | Subscribe to NVD enrichment updates for specific CVE IDs using the NVD API notification stream or a vulnerability intelligence service. |
| **VEX when data is available** | As soon as NVD or vendor advisory provides sufficient detail, complete the VEX assessment. |

**Category 2: Zero-day with no CVE assigned**

When an active exploit or vendor advisory describes a vulnerability in a component your software uses, but no CVE has been assigned:

```
Zero-Day Handling Procedure:
1. Immediately assess the affected component version against the advisory's description.
2. If the advisory indicates affected versions include your version:
   - Treat as Severity = Critical regardless of unassigned CVSS.
   - Apply a 24-hour remediation SLA.
3. Create an internal tracking ID (e.g., INT-VULN-2024-001) in your VEX registry.
4. Document the advisory source URL, disclosure date, and evidence of impact assessment.
5. When CVE is assigned, update VEX registry to link internal ID to the CVE.
6. Do not remove the internal ID entry — it preserves the audit trail of when you
   first learned of the vulnerability.
```

**Category 3: Transitive dependency with no upgrade path**

When a CVE affects a transitive dependency, but upgrading it would break a direct dependency that has not yet released a compatible version:

```
Blocked Upgrade Procedure:
1. Assess whether the CVE is exploitable in your context (VEX assessment).
   - If not exploitable → issue VEX "not_affected" with justification "vulnerable_code_not_in_execute_path"
   - If exploitable → continue to step 2.

2. Document the dependency conflict:
   service X requires library A >= 2.0 which requires library B = 1.4 (vulnerable)
   library B >= 1.5 (fixed) is incompatible with library A 2.0
   library A 3.0 (supports B >= 1.5) not yet released

3. Escalation options (in priority order):
   a. Vendor patch: contact the maintainer of library A and report the conflict.
   b. Fork patch: if library A is open source and non-complex, apply minimal fix
      and use a forked version until upstream releases.
   c. Runtime mitigation: deploy compensating controls (WAF rules, input validation)
      to reduce exploitability. Document as VEX "inline_mitigations_already_exist"
      with security review sign-off.
   d. Risk acceptance: formal risk acceptance from CISO with documented timeline
      for resolution when library A 3.0 is released.

4. Set a calendar reminder for 30 days to re-evaluate — do not set-and-forget.
```

---

### VEX Conflict Resolution

When two teams disagree on whether a CVE affects a shared component, a resolution procedure prevents the disagreement from blocking deployments indefinitely.

**Conflict scenarios:**

| Conflict Type | Resolution Owner | Resolution Procedure |
|---------------|-----------------|---------------------|
| Team A claims `not_affected`; Team B's threat model shows exploitation path | Application Security | Security engineer performs independent code review; findings are binding |
| Two services share a component; one is affected, one is not | Per-service VEX | Issue separate VEX documents per service — VEX is always scoped to a specific product/version |
| Scanner vendor disagrees with internal assessment | Internal assessment governs | Document vendor discrepancy; your VEX assertion is authoritative for your context |
| Previous `not_affected` assertion disputed after code change | Security engineer re-review | Treat as a new assessment; prior assertion is superseded, not amended |

**Escalation path for unresolved conflicts:**

```
Developer team disputes VEX assessment
  └─► Application Security review (3 business days SLA)
        └─► If unresolved: Security Architecture review (5 business days SLA)
              └─► If unresolved: CISO risk decision (binding; documented in exception log)
```

While a conflict is unresolved, the vulnerability is treated as **affected** — the pipeline gate remains active. Teams cannot self-approve a `not_affected` assertion for CVEs that are under dispute.

---

### VEX in Dependency-Track

Dependency-Track (DT) has native CycloneDX VEX support. To configure:

1. Upload the SBOM to Dependency-Track via the API or CI/CD integration.
2. Upload the corresponding VEX document to the same project:
   ```bash
   curl -X POST \
     -H "X-Api-Key: <DT_API_KEY>" \
     -H "Content-Type: multipart/form-data" \
     -F "project=<PROJECT_UUID>" \
     -F "vex=@./payment-service-v3.2.1.vex.json" \
     https://dependency-track.example.com/api/v1/vex
   ```
3. DT automatically applies VEX status to suppress non-applicable findings in its vulnerability dashboard.
4. VEX-suppressed findings are still visible in DT with their suppression justification — they are not deleted.

---

## Part 2: SBOM Lifecycle Management

SBOMs are not static documents. They must be updated when dependencies change, when new vulnerabilities are disclosed, and when build configurations change. An outdated SBOM is worse than no SBOM — it creates false confidence.

### SBOM Versioning Strategy

Every SBOM must be versioned and tied to a specific artifact digest.

**Versioning rules:**
- The SBOM `version` field increments each time the SBOM is regenerated (dependency changes, tooling updates, VEX amendments).
- The SBOM `serialNumber` is a UUID that uniquely identifies a specific SBOM generation event.
- SBOMs are linked to artifacts via the artifact's digest — not its tag (tags are mutable; digests are immutable).

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
  "version": 3,
  "metadata": {
    "timestamp": "2024-03-20T14:00:00Z",
    "component": {
      "type": "container",
      "name": "payment-service",
      "version": "3.2.1",
      "purl": "pkg:docker/myregistry.io/payment-service@sha256:a3f8c7d9...",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "a3f8c7d9..."
        }
      ]
    }
  }
}
```

**SBOM version triggers:** A new SBOM version must be generated when:
- Any direct or transitive dependency version changes
- A new component is added to the artifact
- A component is removed from the artifact
- The base image is updated (for container images)
- The build toolchain version changes (new compiler, runtime, packaging tool)
- An existing VEX assertion needs to be updated

---

### SBOM Storage and Retrieval Architecture

SBOMs and their associated VEX documents must be stored in a location that supports:
- Immutable storage (once stored, cannot be modified)
- Long-term retention (minimum 7 years for most compliance frameworks)
- Content-addressable retrieval (fetch SBOM by artifact digest)
- Access control (SBOMs may contain sensitive dependency information)

**Reference storage architecture:**

```
Artifact Registry
  └── myregistry.io/payment-service@sha256:a3f8c7d9...
        ├── Container image layers
        ├── CycloneDX SBOM (Cosign attestation — type: cyclonedx)
        ├── SPDX SBOM (Cosign attestation — type: spdx)
        ├── SLSA Provenance (Cosign attestation — type: slsaprovenance)
        └── VEX document (Cosign attestation — type: openvex)

Long-term Compliance Archive (separate from operational registry)
  └── s3://compliance-evidence/sboms/YYYY/MM/DD/
        ├── <artifact-digest>.cdx.json
        ├── <artifact-digest>.spdx.json
        ├── <artifact-digest>.vex.json
        └── <artifact-digest>.provenance.json
```

**Storing SBOMs with Cosign (OCI-compatible, digest-linked):**
```bash
# Attach SBOM as Cosign attestation (stored in registry alongside image)
cosign attest \
  --predicate ./sbom.cdx.json \
  --type cyclonedx \
  "$REGISTRY/$IMAGE@$DIGEST"

# Retrieve SBOM for any artifact by digest
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity-regexp "^https://github.com/<org>/<repo>/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  "$REGISTRY/$IMAGE@$DIGEST" \
  | jq '.payload | @base64d | fromjson'
```

**Archival to S3 with Object Lock (immutable long-term storage):**
```bash
# Archive SBOM to compliance bucket with Object Lock retention
aws s3api put-object \
  --bucket compliance-evidence \
  --key "sboms/$(date +%Y/%m/%d)/${DIGEST_SAFE}.cdx.json" \
  --body ./sbom.cdx.json \
  --content-type "application/vnd.cyclonedx+json" \
  --object-lock-mode COMPLIANCE \
  --object-lock-retain-until-date "$(date -d '+7 years' --iso-8601=seconds)"
```

---

### SBOM Patch Cycle Integration

When a new CVE is disclosed affecting a dependency in a deployed artifact, the SBOM workflow must respond:

```
CVE disclosed for <package>@<version>
│
├── Step 1: Query SBOM inventory for affected artifacts
│   # Which of our deployed artifacts contain this package/version?
│   # Use Dependency-Track or SBOM indexing service:
│   curl -H "X-Api-Key: $DT_KEY" \
│     "https://dependency-track.example.com/api/v1/component/identity" \
│     --data-urlencode "purl=pkg:npm/<package>@<version>"
│
├── Step 2: For each affected artifact, determine VEX status
│   ├── If exploitable → trigger patch release pipeline
│   ├── If not affected → author VEX assertion, attach to artifact
│   └── If under investigation → set SLA timer (default: 7 days for Critical)
│
├── Step 3: If patch required → rebuild artifact
│   └── New artifact digest generated
│       └── Generate new SBOM for new artifact
│           └── New SBOM version replaces prior version
│               └── Archive old SBOM (do not delete — compliance evidence)
│
└── Step 4: Update SBOM inventory
    └── Dependency-Track project updated with new artifact SBOM
```

---

### SBOM Completeness and Quality Standards

A generated SBOM is only as useful as its completeness. The NTIA minimum elements for an SBOM are:

| Element | Description | Verification Method |
|---------|-------------|---------------------|
| Supplier name | Name of entity creating the SBOM | Present in `metadata.supplier` |
| Component name | Unique identifier for each component | Present in `components[].name` |
| Version string | Version of each component | Present in `components[].version` |
| Unique identifiers | PURL or CPE for each component | Present in `components[].purl` |
| Dependency relationships | How components depend on each other | Present in `dependencies[]` section |
| Author of SBOM | Who generated the SBOM | Present in `metadata.authors` |
| Timestamp | When the SBOM was generated | Present in `metadata.timestamp` |

**SBOM quality scoring (automated check in CI):**

```python
# Minimal SBOM quality check script
import json, sys

with open('sbom.cdx.json') as f:
    sbom = json.load(f)

components = sbom.get('components', [])
issues = []

for c in components:
    if not c.get('version'):
        issues.append(f"Component '{c.get('name')}' missing version")
    if not c.get('purl') and not c.get('cpe'):
        issues.append(f"Component '{c.get('name')}' missing PURL/CPE identifier")

dependencies = sbom.get('dependencies', [])
if len(dependencies) < len(components) * 0.5:
    issues.append(f"Dependency graph sparse: {len(dependencies)} edges for {len(components)} components")

if issues:
    print(f"SBOM QUALITY ISSUES ({len(issues)}):")
    for issue in issues:
        print(f"  - {issue}")
    sys.exit(1)

print(f"SBOM quality check PASSED: {len(components)} components, {len(dependencies)} dependency relationships")
```

---

### SBOM Retention Policy

| Artifact Type | Minimum Retention | Rationale |
|---------------|------------------|-----------|
| Production artifacts | 7 years | SOC 2, PCI-DSS, ISO 27001 evidence retention |
| Staging artifacts | 1 year | Regression analysis and debugging |
| Development/PR artifacts | 90 days | Short-term debugging and audit |
| SBOMs for artifacts with known regulatory exposure | Per applicable regulation | HIPAA, FedRAMP requirements may extend retention |

**Retention enforcement:**
- Use S3 Object Lock with `COMPLIANCE` mode to prevent deletion during the retention period.
- Automate the application of retention policies in the SBOM archival pipeline step.
- Ensure the archival bucket is in a separate AWS account from the application account (to prevent credential compromise from deleting compliance evidence).

---

### SBOM Edge Cases

Standard SBOM generation workflows cover the common case: a build system produces an artifact, Syft or Trivy generates an SBOM, and the result is stored alongside the image. Several edge cases require explicit handling to avoid incomplete or misleading SBOMs.

#### Edge Case 1: Dynamically Downloaded Dependencies at Runtime

Some applications download plugins, models, or code at runtime rather than at build time. These components are not captured in a build-time SBOM.

**Examples:** ML models pulled from a model hub at startup; plugin systems that fetch extensions on first use; applications that `pip install` or `gem install` from a requirements file at container launch.

**Risk:** A runtime-fetched dependency with a known CVE will not appear in the SBOM. Vulnerability scanners will not detect it. Compliance evidence for component inventory is incomplete.

**Handling approach:**

| Option | When to Use | Implementation |
|--------|-------------|---------------|
| **Prohibit runtime dependency fetching** | Best option for production workloads | Enforce via OPA/Kyverno admission policy: block containers with `command` or `args` that invoke package managers |
| **Generate supplemental SBOM at startup** | When runtime fetching is unavoidable | Run `syft` or `pip-audit` as an init container; upload supplemental SBOM to Dependency-Track via API before the main container starts |
| **Pin all runtime-fetched components** | For ML model scenarios | Pin model identifiers to immutable hashes; add model hashes to a machine-readable `model-registry.json` that is processed as an SBOM supplement |

**Detection:** Audit containers for runtime dependency fetching by scanning the image entrypoint and CMD for `pip`, `gem`, `npm`, `curl | sh`, or `wget` invocations using `syft` or a custom OPA policy at admission.

---

#### Edge Case 2: Multi-Stage Build Artifacts with Layer Squashing

Multi-stage Docker builds are designed to produce a minimal final image, but SBOM tools may capture components from build stages that do not appear in the final artifact, or miss components that are copied without their metadata.

**Problem scenarios:**
- `COPY --from=builder /app/node_modules/` copies compiled binaries without preserving `package.json` — Syft cannot reconstruct the dependency tree from compiled artifacts alone
- A distroless base image provides no package manager database — Syft falls back to heuristic detection which may miss components

**Handling approach:**

```dockerfile
# Build stage — generate SBOM during build while full package metadata is available
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm ci

# Generate SBOM from the build context before squashing
RUN npm list --json > /tmp/npm-tree.json

FROM node:20-alpine AS sbom-generator
COPY --from=builder /tmp/npm-tree.json /tmp/npm-tree.json
RUN apk add --no-cache curl && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin && \
    syft /tmp/npm-tree.json -o cyclonedx-json=/tmp/sbom.cdx.json

FROM gcr.io/distroless/nodejs20-debian12 AS runtime
COPY --from=builder /app/dist/ /app/
# SBOM is produced in the sbom-generator stage and extracted in CI — not included in runtime image
```

```yaml
# GitHub Actions — extract SBOM from build stage before final image is published
- name: Extract SBOM from build stage
  run: |
    docker build --target sbom-generator -t sbom-stage .
    docker create --name sbom-extractor sbom-stage
    docker cp sbom-extractor:/tmp/sbom.cdx.json ./sbom.cdx.json
    docker rm sbom-extractor
    echo "SBOM extracted from build stage — will be attached to final image digest"
```

---

#### Edge Case 3: SBOMs for Monorepos with Multiple Artifacts

A monorepo may produce 10–50 deployable artifacts from a single repository. Generating one SBOM for the repository root will include components from all services, making each per-artifact SBOM inaccurate and inflating vulnerability counts.

**Required approach:** Generate a separate, scoped SBOM per deployable artifact — not per repository.

```yaml
# GitHub Actions — matrix strategy for per-artifact SBOM generation
jobs:
  generate-sboms:
    strategy:
      matrix:
        service:
          - name: payment-service
            path: services/payment
          - name: auth-service
            path: services/auth
          - name: notification-service
            path: services/notification
    steps:
      - name: Build ${{ matrix.service.name }} image
        run: |
          docker build -t ${{ matrix.service.name }}:${{ github.sha }} \
            ${{ matrix.service.path }}

      - name: Generate SBOM for ${{ matrix.service.name }}
        run: |
          syft scan ${{ matrix.service.name }}:${{ github.sha }} \
            -o cyclonedx-json=sbom-${{ matrix.service.name }}.cdx.json

      - name: Attach SBOM to image
        run: |
          IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' \
            ${{ matrix.service.name }}:${{ github.sha }})
          cosign attest \
            --predicate sbom-${{ matrix.service.name }}.cdx.json \
            --type cyclonedx \
            "$IMAGE_DIGEST"
```

**Dependency-Track organization for monorepos:** Create one Dependency-Track *project* per service, not per repository. Use the repository name as the parent tag and service name as the project name. This allows per-service vulnerability queries and per-service VEX management.

---

#### Edge Case 4: SBOMs for Infrastructure (Terraform, Helm, CloudFormation)

Infrastructure-as-Code artifacts have software dependencies (provider versions, module versions, Helm chart dependencies) that are rarely included in SBOM programs but represent a real supply chain risk.

**IaC SBOM generation:**

```bash
# Generate SBOM for Terraform module dependencies
# cdxgen supports HCL/Terraform natively
cdxgen -t terraform ./infrastructure/ -o terraform-sbom.cdx.json

# Generate SBOM for Helm chart dependencies
# Syft supports OCI artifacts including Helm charts
syft oci-archive:$(helm package my-chart --dependency-update | grep -oP '(?<=to: ).+') \
  -o cyclonedx-json=helm-sbom.cdx.json

# Attach Terraform SBOM to the Terraform state version identifier
# Store with the commit SHA that modified the infrastructure
aws s3 cp terraform-sbom.cdx.json \
  s3://compliance-evidence/iac-sboms/${COMMIT_SHA}/terraform-sbom.cdx.json
```

**What IaC SBOMs capture that standard SBOMs miss:**
- Terraform provider versions (hashicorp/aws, hashicorp/kubernetes) — these are software with CVEs
- Helm chart versions and their Docker image dependencies
- CloudFormation transform versions
- Ansible role and collection versions

---

#### Edge Case 5: SBOMs for Database Migrations and Schema Artifacts

Database migrations are deployed artifacts that are rarely included in SBOM programs. A migration script that embeds a vulnerable serialization library (e.g., a Python Alembic migration that imports a vulnerable dependency) is a real supply chain risk.

**Handling approach:**
- Treat migration bundles as first-class artifacts alongside application images
- Generate SBOMs for migration runner containers (which contain the Python/Ruby/Go dependencies needed to execute migrations)
- Pin migration runner base images to signed, scanned images — do not use `python:latest` as the migration runner

See `release-orchestration-framework/docs/database-migration-safety.md` for the full migration safety framework, including how migration artifacts fit into the signed artifact promotion pipeline.

---

### SBOM Registry Integration Checklist

Use this checklist to verify SBOM lifecycle management is operational:

```
SBOM Generation
[ ] SBOM generated for every artifact in CI/CD pipeline
[ ] SBOM attached to artifact digest via Cosign attestation
[ ] SBOM quality score checked (NTIA minimum elements met)
[ ] CycloneDX and SPDX formats both generated for regulated artifacts

SBOM Storage
[ ] SBOM stored in registry (linked to artifact digest)
[ ] SBOM archived to compliance bucket with retention policy
[ ] Compliance bucket uses Object Lock (COMPLIANCE mode)
[ ] Compliance archive is in a separate account from the application account

VEX Integration
[ ] VEX document process defined for all CRITICAL/HIGH CVEs
[ ] VEX approvals recorded with approver identity and timestamp
[ ] VEX documents attached to artifact as Cosign attestation
[ ] VEX applied to vulnerability scanner results before gate evaluation
[ ] VEX review schedule set (30/90/180 days based on severity)

SBOM Versioning
[ ] SBOM version increments on each regeneration
[ ] SBOM linked to artifact by digest (not mutable tag)
[ ] Old SBOMs retained (not overwritten) when new versions generated

Inventory and Querying
[ ] Dependency-Track or equivalent SBOM management platform deployed
[ ] All production artifact SBOMs loaded into inventory platform
[ ] CVE-to-affected-artifact queries operational (to respond to new disclosures)
[ ] SBOM export procedure documented for audit requests
```

---

*See also:*
- *[sbom-guide.md](sbom-guide.md) — SBOM format selection and generation tool comparison*
- *[framework.md](framework.md) — supply chain security controls framework*
- *[incident-response-playbook.md](incident-response-playbook.md) — response procedures when supply chain compromise is suspected*
- *[compliance-automation-framework: framework.md](../../compliance-automation-framework/docs/framework.md) — compliance evidence retention requirements*
