# License Compliance Integration

Software licenses define the legal obligations attached to open-source dependencies. Failure to comply with license terms can create legal liability, require source code disclosure, or void distribution rights. In a supply chain security context, license compliance is inseparable from dependency management: the same pipeline controls that govern security risks in dependencies must also govern license risks.

This guide covers license risk classification, automated license scanning, SBOM-driven license auditing, and integration with the software supply chain security controls defined in the [Software Supply Chain Security Framework](../README.md).

---

## License Risk Classification

Not all open-source licenses impose the same obligations. License risk is classified by the obligations and restrictions they impose on your software distribution and use.

### Tier 1 — Permissive (Green — Low Risk)

These licenses permit use, modification, and distribution with minimal restrictions. Attribution is typically required.

| License | Key Obligations | Common Use Cases |
|---------|---------------|-----------------|
| **MIT** | Attribution in distributed software | Extremely common; low friction |
| **Apache 2.0** | Attribution; patent grant (protective) | Common in enterprise open source |
| **BSD 2-Clause / 3-Clause** | Attribution | Common in academia and infrastructure |
| **ISC** | Attribution | Node.js ecosystem |
| **0BSD / Unlicense / CC0** | None | Public domain dedications |

**Policy:** Approved by default for all use cases including SaaS, commercial distribution, and embedding in proprietary software.

### Tier 2 — Weak Copyleft (Yellow — Review Required)

Weak copyleft licenses require that modifications to the licensed component itself be released under the same license, but do not "infect" the broader work that uses the component.

| License | Key Obligations | Risk Trigger |
|---------|---------------|-------------|
| **LGPL 2.1 / 3.0** | Modifications to the LGPL library must be shared; dynamic linking typically safe | Static linking, combined works |
| **MPL 2.0** | File-level copyleft — modified MPL files must be open-sourced | Modifying MPL source files |
| **CDDL** | File-level copyleft similar to MPL | Modifying CDDL source files |
| **EPL 1.0 / 2.0** | Modifications to EPL code must be shared | Modifying EPL source files |

**Policy:** Permitted with legal team review for embedded or distributed use cases. Using unchanged LGPL/MPL libraries in SaaS (not distributed software) is generally low risk.

### Tier 3 — Strong Copyleft (Red — Approval Required)

Strong copyleft licenses require that any software derived from or combined with the licensed code be released under the same license when distributed.

| License | Key Obligations | Risk Trigger |
|---------|---------------|-------------|
| **GPL 2.0** | All combined/derivative works must be GPL if distributed | Any distribution of software linking GPL code |
| **GPL 3.0** | Same as GPL 2.0 + anti-tivoization | Same |
| **AGPL 3.0** | GPL 3.0 obligations + SaaS distribution triggers copyleft | Running GPL-A code in a network service |
| **OSL 3.0** | Network-triggered copyleft similar to AGPL | Network service use |

**Policy:** Requires explicit legal team approval before introducing into any codebase that will be distributed to customers or deployed as a commercial service.

### Tier 4 — Restricted / Non-OSS (Red — Prohibited Without Contract)

| License Type | Examples | Policy |
|-------------|---------|--------|
| Commercial licenses | Proprietary SDKs, non-free dependencies | Permitted only with active commercial agreement tracked in vendor register |
| Non-commercial licenses | CC BY-NC, many "source-available" licenses | Prohibited for commercial use |
| Server-side public license (SSPL) | MongoDB, Elasticsearch early versions | Effectively AGPL-like — requires legal review |
| No license stated | Unlicensed code | Prohibited — all rights reserved by default |

---

## Automated License Scanning

### SBOM-Driven License Analysis

The software supply chain security controls in this framework require SBOM generation for all production artifacts. The SBOM is the foundation for automated license compliance:

```bash
# Generate SBOM with license information (CycloneDX)
trivy image \
  --format cyclonedx \
  --output sbom.json \
  your-app:${BUILD_TAG}

# CycloneDX SBOMs include a "licenses" field per component
# Example component entry in the SBOM:
# {
#   "name": "express",
#   "version": "4.18.2",
#   "licenses": [{"license": {"id": "MIT"}}],
#   "purl": "pkg:npm/express@4.18.2"
# }
```

### License Scanning in CI/CD Pipelines

**GitHub Actions — license gate:**

```yaml
- name: Scan dependency licenses
  run: |
    # Install license-checker (Node.js projects)
    npx license-checker \
      --production \
      --json \
      --out license-report.json

    # Fail if any Tier 3/4 licenses detected
    python3 scripts/check-licenses.py \
      --report license-report.json \
      --policy .license-policy.yml \
      --fail-on DISALLOWED

- name: Upload license report
  uses: actions/upload-artifact@v4
  with:
    name: license-report
    path: license-report.json
    retention-days: 365  # Retain for compliance evidence
```

**.license-policy.yml — policy definition:**

```yaml
# License compliance policy for Techstream projects
version: "1.0"

allowed:
  - MIT
  - Apache-2.0
  - BSD-2-Clause
  - BSD-3-Clause
  - ISC
  - Unlicense
  - 0BSD
  - CC0-1.0

review_required:
  - LGPL-2.0
  - LGPL-2.1
  - LGPL-3.0
  - MPL-2.0
  - EPL-1.0
  - EPL-2.0

disallowed:
  - GPL-2.0
  - GPL-3.0
  - AGPL-3.0
  - SSPL-1.0
  - CC-BY-NC-4.0
  - UNLICENSED  # No license declared — all rights reserved

# Per-package exceptions (requires legal approval and expiry date)
exceptions:
  - package: "some-gpl-tool"
    license: "GPL-3.0"
    reason: "Build-time tool only — not linked into distributed artifact"
    approved_by: "legal@example.com"
    expires: "2027-01-01"
    jira_ticket: "SEC-4821"
```

**Python/Java projects — using FOSSA or licensee:**

```bash
# FOSSA CLI — comprehensive license analysis for multiple ecosystems
fossa analyze --format json --output fossa-report.json

# licensee — Ruby/GitHub's license detection tool
licensee detect --json . > licensee-report.json

# For Java/Maven: Apache License Maven Plugin
mvn license:aggregate-add-third-party license:check \
  -Dlicense.failIfWarning=true
```

### License Scanning for Container Images

Container images may include OS packages with different license obligations than application dependencies:

```bash
# Trivy — scan OS packages and application dependencies for licenses
trivy image \
  --scanners license \
  --license-full \
  --format json \
  --output container-license-report.json \
  your-app:${BUILD_TAG}

# Filter to non-permissive licenses
jq '[.Results[] | .Licenses[] | select(.Category != "permissive")] |
    group_by(.Name) |
    map({license: .[0].Name, packages: map(.PkgName)})' \
  container-license-report.json
```

---

## SBOM License Inventory Management

### Dependency-Track License Dashboard

For fleet-scale license management, use Dependency-Track to maintain a queryable license inventory across all projects:

```python
# Upload SBOM to Dependency-Track for license tracking
import requests

def upload_sbom(
    dt_url: str,
    api_key: str,
    project_name: str,
    project_version: str,
    sbom_path: str,
) -> str:
    import base64

    with open(sbom_path, "rb") as f:
        sbom_b64 = base64.b64encode(f.read()).decode()

    response = requests.put(
        f"{dt_url}/api/v1/bom",
        headers={"X-Api-Key": api_key, "Content-Type": "application/json"},
        json={
            "projectName": project_name,
            "projectVersion": project_version,
            "autoCreate": True,
            "bom": sbom_b64,
        },
    )
    response.raise_for_status()
    return response.json().get("token")
```

**Querying the license inventory:**

```bash
# Find all projects using GPL-licensed components via Dependency-Track API
curl -s \
  -H "X-Api-Key: ${DT_API_KEY}" \
  "${DT_URL}/api/v1/license/GPL-3.0/project" \
  | jq '.[] | {project: .name, version: .version}'

# Export full organization license inventory
curl -s \
  -H "X-Api-Key: ${DT_API_KEY}" \
  "${DT_URL}/api/v1/reporting/export/metrics/component" \
  | jq '.[] | select(.license != null) | {project: .project.name, component: .name, license: .license.spdxId}'
```

---

## License Obligation Tracking

Identifying license obligations is necessary but not sufficient — obligations must be documented and fulfilled.

### Attribution Requirements

The most common obligation across Tier 1 licenses is attribution: the license notice must appear in distributed software. Automated attribution generation prevents missing attributions:

```bash
# Node.js — generate NOTICE file from installed dependencies
npx license-checker \
  --production \
  --customPath legal/attribution-template.json \
  --out NOTICE.md \
  --direct 0

# Python — pip-licenses
pip install pip-licenses
pip-licenses \
  --format=markdown \
  --with-authors \
  --with-urls \
  --output-file NOTICE.md

# Java/Maven — generate attribution report
mvn license:aggregate-add-third-party \
  -Dlicense.thirdPartyFilename=NOTICE.txt
```

**NOTICE.md format standard:**

```markdown
# Third-Party Software Notices

This product includes software developed by third parties under the following licenses:

## MIT License

### express (4.18.2)
Copyright (c) 2009-2014 TJ Holowaychuk <tj@vision-media.ca>
Copyright (c) 2013-2014 Roman Shtylman <shtylman+expressjs@gmail.com>
Copyright (c) 2014-2015 Douglas Christopher Wilson <doug@somethingdoug.com>
[Full MIT License text]

...
```

### Distribution Checklist

When distributing software (on-premises delivery, container images, SDK distribution):

- [ ] NOTICE.md generated and included in the distribution artifact
- [ ] No AGPL, GPL, or LGPL dependencies linked into closed-source components (or legal approval on file)
- [ ] All modified open-source files retain their original copyright notices
- [ ] License exceptions documented with approval and expiry dates
- [ ] SBOM attached to the release artifact (for downstream consumers' license analysis)

---

## License Exception Management

When a dependency with a restricted license is genuinely required, a formal exception process prevents ad hoc bypass:

### Exception Request Fields

| Field | Required | Description |
|-------|----------|-------------|
| Package name and version | Yes | Exact PURL (e.g., `pkg:npm/some-package@1.2.3`) |
| License identifier | Yes | SPDX identifier |
| Use case | Yes | How the package is used (runtime, build-time, test-only) |
| Distribution scope | Yes | SaaS-only, on-prem distribution, internal only |
| Risk assessment | Yes | Why the license terms apply or do not apply in this context |
| Alternatives evaluated | Yes | Permissive-licensed alternatives considered and why not chosen |
| Legal team approval | Yes | Approval record with approver identity and date |
| Expiry date | Yes | When the exception must be re-reviewed (max 12 months) |
| Jira/issue reference | Yes | Traceability to the approval workflow |

### Exception in CI Policy

Exceptions are tracked in `.license-policy.yml` (shown above) with mandatory expiry. The CI license gate fails if any exception is expired:

```python
# scripts/check-licenses.py — excerpt
from datetime import date

def check_exceptions(policy: dict) -> list[str]:
    today = date.today()
    errors = []
    for exc in policy.get("exceptions", []):
        expires = date.fromisoformat(exc["expires"])
        if today > expires:
            errors.append(
                f"License exception for {exc['package']} expired on {exc['expires']}. "
                f"Renew or remove the dependency. Ticket: {exc.get('jira_ticket', 'none')}"
            )
    return errors
```

---

## Integration with Software Supply Chain Security Controls

License compliance is a dimension of supply chain security, not a separate concern. The controls in this framework reinforce each other:

| Supply Chain Control | License Compliance Integration |
|---------------------|-------------------------------|
| **SBOM generation** | SBOM contains license metadata for all components — single source of truth for both security and license compliance |
| **Dependency pinning** | Pinned dependencies ensure the license in the SBOM matches what is actually installed — no silent license changes on dependency update |
| **Private registry mirror** | Registry mirror can enforce a license allowlist — packages with disallowed licenses are blocked at the mirror before they reach CI |
| **Dependency-Track** | License inventory visible alongside vulnerability inventory — single platform for supply chain risk management |
| **VEX workflow** | License exceptions can be modeled analogously to VEX statements for vulnerability false positives |

### Private Registry License Enforcement

Configure the private package mirror to block packages with disallowed licenses at the registry level:

```yaml
# Artifactory license enforcement rule
# Block packages with GPL/AGPL licenses from being proxied
restrictions:
  - name: "Block GPL"
    filter:
      licenses:
        - "GPL-2.0"
        - "GPL-3.0"
        - "AGPL-3.0"
        - "SSPL-1.0"
    action: block
    message: "Package license not approved. Submit a license exception request before adding this dependency."
```

---

## License Compliance Metrics

Track these metrics to demonstrate license compliance posture to auditors and procurement:

| Metric | Collection Method | Target |
|--------|-----------------|--------|
| % of components with known license | Dependency-Track / SBOM analysis | 100% |
| % of components with approved license | CI license gate | 100% |
| Open license exceptions | Exception register | Trending toward 0; all within expiry |
| Expired license exceptions | Automated check in CI | 0 (fails CI if any exist) |
| Projects with NOTICE.md generated | CI artifact check | 100% of distributed projects |

---

## Related Techstream Resources

| Topic | Document |
|-------|---------|
| SBOM generation and lifecycle | [SBOM Guide](sbom-guide.md) |
| SBOM at enterprise scale | [SBOM at Scale](sbom-at-scale.md) |
| Open source dependency assessment | [Open Source Component Assessment](open-source-component-assessment.md) |
| VEX and SBOM lifecycle | [VEX and SBOM Lifecycle](vex-and-sbom-lifecycle.md) |
| Vendor assessment | [Vendor Security Assessment](vendor-security-assessment.md) |
| Dependency-Track integration | [Software Supply Chain Framework](implementation.md) |

*Part of the Techstream Software Supply Chain Security Framework. Licensed under Apache 2.0.*
