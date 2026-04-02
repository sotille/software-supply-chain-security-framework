# Software Supply Chain Security Implementation Guide

## Table of Contents

- [Implementation Overview](#implementation-overview)
- [Phase 1: Quick Wins and Visibility (Months 1–3)](#phase-1-quick-wins-and-visibility-months-13)
- [Phase 2: SBOM and Signing (Months 4–6)](#phase-2-sbom-and-signing-months-46)
- [Phase 3: SLSA Maturity and Policy Enforcement (Months 7–9)](#phase-3-slsa-maturity-and-policy-enforcement-months-79)
- [Phase 4: Advanced Controls (Months 10–12)](#phase-4-advanced-controls-months-1012)
- [SBOM Tooling Setup](#sbom-tooling-setup)
- [Sigstore/Cosign Deployment](#sigstore-cosign-deployment)
- [SLSA Level Progression](#slsa-level-progression)
- [Dependency Scanning Pipeline Integration](#dependency-scanning-pipeline-integration)
- [Private Artifact Registry Setup](#private-artifact-registry-setup)
- [Admission Controller Configuration](#admission-controller-configuration)
- [Third-Party Vendor Assessment Process](#third-party-vendor-assessment-process)

---

## Implementation Overview

Supply chain security implementation is a multi-year program requiring coordination across security, engineering, and platform teams. The approach presented here prioritizes quick wins that deliver immediate risk reduction and visibility, followed by progressive investment in deeper controls.

**Key principles:**
- Start with visibility: you cannot secure what you cannot see. SBOM generation and dependency scanning provide immediate value.
- Automate enforcement gradually: begin with audit mode (detect but don't block) and transition to enforce mode after validating accuracy.
- Focus on critical services first: apply the highest-assurance controls to your most critical software before broad rollout.
- Integrate with existing pipelines: supply chain security controls should augment CI/CD pipelines, not replace them.

---

## Phase 1: Quick Wins and Visibility (Months 1–3)

### Objectives
Establish dependency visibility, activate vulnerability scanning, enforce dependency pinning, and deploy a private artifact registry.

### Month 1: Inventory and Scanning

**Week 1–2: Dependency inventory**

Conduct a dependency inventory across all production repositories using Syft or Trivy:

```bash
# Scan all container images in production
for image in $(kubectl get pods -A -o jsonpath='{.items[*].spec.containers[*].image}' | tr ' ' '\n' | sort -u); do
  echo "=== Scanning: $image ==="
  syft "$image" -o cyclonedx-json > "sboms/$(echo $image | tr '/:' '__').json"
done

# Generate inventory report
grype sboms/*.json --output table --fail-on critical
```

**Week 3–4: Vulnerability scanning activation**

Add vulnerability scanning to all CI pipelines using Trivy or Grype:

```yaml
# .github/workflows/security-scan.yml
name: Security Scanning

on: [push, pull_request]

jobs:
  vulnerability-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run Trivy vulnerability scanner (filesystem)
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: fs
          scan-ref: .
          format: sarif
          output: trivy-results.sarif
          severity: CRITICAL,HIGH
          exit-code: 0  # Audit mode: don't fail yet

      - name: Upload Trivy scan results to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: trivy-results.sarif
```

### Month 2: Dependency Pinning and Registry Setup

**Dependency pinning enforcement**

Configure Renovate Bot for automated, safe dependency update PRs:

```json
// renovate.json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:base", "security:openssf-scorecard"],
  "dependencyDashboard": true,
  "schedule": ["after 6pm every weekday", "every weekend"],
  "prConcurrentLimit": 5,
  "rangeStrategy": "pin",
  "lockFileMaintenance": {
    "enabled": true,
    "schedule": ["before 5am on Monday"]
  },
  "vulnerabilityAlerts": {
    "labels": ["security"],
    "enabled": true
  },
  "osvVulnerabilityAlerts": true
}
```

**Private registry deployment (Harbor)**

```yaml
# harbor-values.yaml (Helm chart values)
expose:
  type: ingress
  tls:
    enabled: true
    certSource: secret
    secret:
      secretName: harbor-tls
  ingress:
    hosts:
      core: registry.example.com

externalURL: https://registry.example.com

persistence:
  enabled: true
  persistentVolumeClaim:
    registry:
      size: 500Gi

trivy:
  enabled: true
  ignoreUnfixed: false

notary:
  enabled: true  # Enables Notary v2 content trust

jobservice:
  replicas: 2

registry:
  replicas: 2
```

```bash
# Install Harbor with Helm
helm repo add harbor https://helm.goharbor.io
helm install harbor harbor/harbor \
  --namespace harbor \
  --create-namespace \
  -f harbor-values.yaml
```

### Month 3: License Compliance and Scoring

**OpenSSF Scorecard integration**

```yaml
# .github/workflows/scorecard.yml
name: Scorecard supply-chain security
on:
  schedule:
    - cron: '0 6 * * 1'  # Weekly on Monday
  push:
    branches: [main]

jobs:
  analysis:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      id-token: write
      contents: read
      actions: read

    steps:
      - name: Checkout
        uses: actions/checkout@v4
        with:
          persist-credentials: false

      - name: Run analysis
        uses: ossf/scorecard-action@v2.3.3
        with:
          results_file: scorecard-results.sarif
          results_format: sarif
          publish_results: true

      - name: Upload to code-scanning
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scorecard-results.sarif
```

**Phase 1 Success Criteria:**
- All production container images inventoried with SBOM
- Vulnerability scanning active on all CI pipelines
- Critical vulnerability count in production: baseline measured
- Private registry deployed and receiving traffic
- Dependency pinning rate: > 80% of production services

---

## Phase 2: SBOM and Signing (Months 4–6)

### Objectives
Implement systematic SBOM generation and artifact signing for all production services.

### SBOM Generation in CI Pipeline

```yaml
# .github/workflows/build-and-sbom.yml
name: Build with SBOM

on:
  push:
    branches: [main]

env:
  REGISTRY: registry.example.com
  IMAGE_NAME: ${{ github.repository }}

jobs:
  build-and-sign:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
      id-token: write  # For Cosign keyless signing

    outputs:
      image-digest: ${{ steps.build.outputs.digest }}

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v3

      - name: Log in to registry
        uses: docker/login-action@v3
        with:
          registry: ${{ env.REGISTRY }}
          username: ${{ secrets.REGISTRY_USERNAME }}
          password: ${{ secrets.REGISTRY_PASSWORD }}

      - name: Build and push container image
        id: build
        uses: docker/build-push-action@v5
        with:
          context: .
          push: true
          tags: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}:${{ github.sha }}
          provenance: true
          sbom: true  # Docker BuildKit SBOM generation

      - name: Generate detailed SBOM with Syft
        run: |
          syft ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }} \
            -o cyclonedx-json \
            --file sbom.json
          echo "SBOM generated with $(jq '.components | length' sbom.json) components"

      - name: Scan SBOM for vulnerabilities
        uses: anchore/scan-action@v3
        id: scan
        with:
          image: ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}
          fail-build: true
          severity-cutoff: critical
          output-format: cyclonedx-json

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Sign container image
        run: |
          cosign sign --yes \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}

      - name: Attest SBOM
        run: |
          cosign attest --yes \
            --predicate sbom.json \
            --type cyclonedx \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}

      - name: Attest vulnerability scan results
        run: |
          cosign attest --yes \
            --predicate ${{ steps.scan.outputs.cyclonedx }} \
            --type https://cyclonedx.org/bom \
            ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}
```

### Dependency-Track Deployment (SBOM Management)

```yaml
# dependency-track-values.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dependency-track
  namespace: security
spec:
  replicas: 1
  template:
    spec:
      containers:
        - name: apiserver
          image: dependencytrack/apiserver:4.10.0
          env:
            - name: ALPINE_DATABASE_MODE
              value: "external"
            - name: ALPINE_DATABASE_URL
              value: "jdbc:postgresql://postgres:5432/dtrack"
            - name: ALPINE_DATABASE_USERNAME
              valueFrom:
                secretKeyRef:
                  name: dtrack-db-credentials
                  key: username
```

**Automated SBOM ingestion into Dependency-Track:**

```python
# upload_sbom.py
import requests
import base64
import json
import sys

DTRACK_URL = "https://dependency-track.internal"
DTRACK_API_KEY = os.environ["DTRACK_API_KEY"]

def upload_sbom(project_name: str, project_version: str, sbom_path: str):
    with open(sbom_path, "rb") as f:
        sbom_b64 = base64.b64encode(f.read()).decode()

    response = requests.put(
        f"{DTRACK_URL}/api/v1/bom",
        headers={"X-Api-Key": DTRACK_API_KEY, "Content-Type": "application/json"},
        json={
            "projectName": project_name,
            "projectVersion": project_version,
            "autoCreate": True,
            "bom": sbom_b64
        }
    )
    response.raise_for_status()
    token = response.json()["token"]
    print(f"SBOM upload initiated. Processing token: {token}")
    return token

if __name__ == "__main__":
    upload_sbom(
        project_name=sys.argv[1],
        project_version=sys.argv[2],
        sbom_path=sys.argv[3]
    )
```

---

## Phase 3: SLSA Maturity and Policy Enforcement (Months 7–9)

### Objectives
Achieve SLSA Level 3 for all Platinum and Gold tier services; deploy admission control policies in production.

### SLSA Level 3 with GitHub Actions

```yaml
# .github/workflows/slsa-build.yml
name: SLSA Level 3 Build

on:
  push:
    branches: [main]

jobs:
  # Step 1: Build the container
  build:
    outputs:
      image: ${{ steps.image.outputs.image }}
      digest: ${{ steps.build.outputs.digest }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Set image
        id: image
        run: echo "image=registry.example.com/${{ github.repository }}" >> $GITHUB_OUTPUT
      - uses: docker/login-action@v3
        with:
          registry: registry.example.com
          username: ${{ secrets.REGISTRY_USERNAME }}
          password: ${{ secrets.REGISTRY_PASSWORD }}
      - name: Build and push
        id: build
        uses: docker/build-push-action@v5
        with:
          push: true
          tags: ${{ steps.image.outputs.image }}:${{ github.sha }}

  # Step 2: Generate SLSA provenance (Level 3)
  # This uses the SLSA GitHub Generator which produces non-falsifiable provenance
  provenance:
    needs: build
    permissions:
      actions: read
      id-token: write
      packages: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
    with:
      image: ${{ needs.build.outputs.image }}
      digest: ${{ needs.build.outputs.digest }}
      registry-username: ${{ secrets.REGISTRY_USERNAME }}
    secrets:
      registry-password: ${{ secrets.REGISTRY_PASSWORD }}
```

### Kyverno Admission Controller Deployment

```bash
# Install Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno/
helm install kyverno kyverno/kyverno \
  --namespace kyverno \
  --create-namespace \
  --set admissionController.replicas=3 \
  --set backgroundController.enable=true \
  --set reportController.enable=true
```

```yaml
# supply-chain-policy.yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: supply-chain-security-policy
  annotations:
    policies.kyverno.io/title: Supply Chain Security Policy
    policies.kyverno.io/category: Supply Chain
    policies.kyverno.io/severity: high
spec:
  validationFailureAction: Enforce
  background: true
  rules:
    # Rule 1: Require signed images
    - name: require-cosign-signature
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, staging]
      verifyImages:
        - imageReferences:
            - "registry.example.com/*"
          attestors:
            - count: 1
              entries:
                - keyless:
                    subject: "https://github.com/example-org/*/github/workflows/*.yml@refs/heads/main"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
          mutateDigest: true
          required: true

    # Rule 2: Require SBOM attestation
    - name: require-sbom-attestation
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production]
      verifyImages:
        - imageReferences:
            - "registry.example.com/*"
          attestations:
            - predicateType: https://cyclonedx.org/bom
              attestors:
                - entries:
                    - keyless:
                        subject: "https://github.com/example-org/*/github/workflows/*.yml@refs/heads/main"
                        issuer: "https://token.actions.githubusercontent.com"

    # Rule 3: Require SLSA provenance
    - name: require-slsa-provenance
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production]
              selector:
                matchLabels:
                  service-tier: platinum
      verifyImages:
        - imageReferences:
            - "registry.example.com/*"
          attestations:
            - predicateType: https://slsa.dev/provenance/v0.2
              attestors:
                - entries:
                    - keyless:
                        subject: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v*"
                        issuer: "https://token.actions.githubusercontent.com"
              conditions:
                - all:
                    - key: "{{ builder.id }}"
                      operator: Equals
                      value: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v*"
```

---

## Phase 4: Advanced Controls (Months 10–12)

### Objectives
Implement hermetic builds for critical services, activate VEX (Vulnerability Exploitability eXchange) workflows, and integrate supply chain security with release orchestration gates.

### VEX Integration

VEX (Vulnerability Exploitability eXchange) allows artifact producers to communicate whether a disclosed vulnerability affects their specific use of a component:

```json
// vex-statement.json (CycloneDX VEX)
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "vulnerabilities": [
    {
      "id": "CVE-2023-12345",
      "source": {"name": "NVD", "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-12345"},
      "analysis": {
        "state": "not_affected",
        "justification": "code_not_reachable",
        "detail": "The vulnerable code path in library X is only invoked when configuration option Y is enabled. Our application does not enable option Y."
      },
      "affects": [
        {"ref": "pkg:maven/org.example/some-library@1.2.3"}
      ]
    }
  ]
}
```

---

## SBOM Tooling Setup

### Syft

Syft is an open source SBOM generator from Anchore. It supports container images, filesystems, and source code trees.

```bash
# Installation
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Generate SBOM for container image
syft registry.example.com/payment-service:sha256-abc123 \
  -o cyclonedx-json=payment-service.cdx.json \
  -o spdx-json=payment-service.spdx.json

# Generate SBOM for filesystem (run at build time before dockerization)
syft dir:/path/to/project -o cyclonedx-json=project.cdx.json

# Generate SBOM for a JAR
syft file:payment-service.jar -o cyclonedx-json=jar.cdx.json
```

### Trivy

Trivy provides SBOM generation combined with vulnerability scanning:

```bash
# Install Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Generate SBOM and scan for vulnerabilities in one pass
trivy image \
  --format cyclonedx \
  --output payment-service.cdx.json \
  --severity CRITICAL,HIGH \
  --exit-code 1 \
  registry.example.com/payment-service:sha256-abc123

# Scan an existing SBOM file for vulnerabilities
trivy sbom payment-service.cdx.json \
  --severity CRITICAL,HIGH \
  --exit-code 1
```

### cdxgen

cdxgen generates CycloneDX SBOMs from source code with deep language ecosystem support:

```bash
# Installation
npm install -g @cyclonedx/cdxgen

# Generate SBOM for Java project
cdxgen -t java -o payment-service.cdx.json .

# Generate SBOM for Python project with transitive dependencies
cdxgen -t python --resolve-class-names -o app.cdx.json .

# Generate SBOM for Node.js project
cdxgen -t nodejs -o frontend.cdx.json .

# Multi-language project
cdxgen --auto-detect -o app.cdx.json .
```

---

## Sigstore/Cosign Deployment

### Using Sigstore Public Good Instance (Recommended for Most Organizations)

No infrastructure deployment required. Configure GitHub Actions to use keyless signing:

```yaml
- name: Install Cosign
  uses: sigstore/cosign-installer@v3.4.0

- name: Sign image (keyless)
  run: |
    cosign sign --yes \
      registry.example.com/my-image@${{ steps.build.outputs.digest }}
  env:
    COSIGN_EXPERIMENTAL: "true"
```

### Private Sigstore Instance (For Air-Gapped or High-Security Environments)

Deploy private Fulcio and Rekor instances:

```bash
# Deploy Fulcio (Certificate Authority)
helm repo add sigstore https://sigstore.github.io/helm-charts
helm install fulcio sigstore/fulcio \
  --namespace sigstore-system \
  --create-namespace \
  --set config.OIDCIssuers[0].IssuerURL=https://token.actions.githubusercontent.com \
  --set config.OIDCIssuers[0].ClientID=sigstore \
  --set config.OIDCIssuers[0].Type=github-workflow

# Deploy Rekor (Transparency Log)
helm install rekor sigstore/rekor \
  --namespace sigstore-system \
  --set trillian.enabled=true
```

---

## SLSA Level Progression

### Assessment Tool

Use the SLSA official tooling to assess current level:

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Verify a container image provenance
slsa-verifier verify-image \
  registry.example.com/payment-service@sha256:abc123 \
  --source-uri github.com/example-org/payment-service \
  --source-branch main \
  --provenance-repository registry.example.com/payment-service

# Check output for SLSA level
# Output: PASSED: SLSA level 3 (or higher)
```

### SLSA Level Progression by Service Tier

| Service Tier | Target Level | Timeline |
|---|---|---|
| Platinum | SLSA 3 | Phase 3 complete |
| Gold | SLSA 2 | Phase 2 complete |
| Silver | SLSA 1 | Phase 1 complete |
| Bronze | SLSA 1 | Phase 2 complete |

---

## Dependency Scanning Pipeline Integration

### Complete Pipeline with All Scanning

```yaml
# .github/workflows/complete-security-pipeline.yml
name: Complete Security Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:

jobs:
  dependency-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Secret scanning
      - name: Detect secrets
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD
          extra_args: --only-verified

      # SAST
      - name: Run Semgrep SAST
        uses: semgrep/semgrep-action@v1
        with:
          config: "p/security-audit p/owasp-top-ten"

      # Dependency vulnerability scan (SCA)
      - name: Run OSV Scanner
        uses: google/osv-scanner-action@v1
        with:
          scan-args: |-
            --lockfile=package-lock.json
            --lockfile=requirements.txt
            --call-analysis=all
            ./

      # License compliance
      - name: License compliance check
        uses: fossas/fossa-action@main
        with:
          api-key: ${{ secrets.FOSSA_API_KEY }}

      # Container image scan (post-build)
      - name: Build image
        run: docker build -t test-image:$GITHUB_SHA .

      - name: Scan container image
        uses: aquasecurity/trivy-action@master
        with:
          image-ref: test-image:${{ github.sha }}
          format: sarif
          output: trivy-container.sarif
          severity: CRITICAL,HIGH
          exit-code: 1

      - name: Upload scan results
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: trivy-container.sarif
```

---

## Private Artifact Registry Setup

### Harbor Configuration for Supply Chain Security

```bash
# 1. Configure proxy cache for Docker Hub
curl -X POST https://registry.example.com/api/v2.0/registries \
  -H "Authorization: Basic $(echo -n 'admin:password' | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "dockerhub-proxy",
    "type": "docker-hub",
    "url": "https://hub.docker.com",
    "insecure": false
  }'

# 2. Create proxy project for Docker Hub
curl -X POST https://registry.example.com/api/v2.0/projects \
  -H "Authorization: Basic $(echo -n 'admin:password' | base64)" \
  -H "Content-Type: application/json" \
  -d '{
    "project_name": "dockerhub",
    "registry_id": 1,
    "public": false,
    "metadata": {"auto_scan": "true"}
  }'

# 3. Enable content trust (Notary)
# Configure in Harbor UI: Administration > Configuration > Security > Enable Content Trust

# 4. Configure vulnerability scan policy
curl -X PUT "https://registry.example.com/api/v2.0/projects/production/scanner" \
  -H "Authorization: Basic $(echo -n 'admin:password' | base64)" \
  -d '{"uuid": "trivy-scanner-uuid"}'
```

### npm Private Registry with Verdaccio

```yaml
# verdaccio-config.yaml
storage: /data/storage
auth:
  htpasswd:
    file: /data/htpasswd
    max_users: -1  # Allow new registrations via admin only

uplinks:
  npmjs:
    url: https://registry.npmjs.org/
    timeout: 30s
    maxage: 10m

packages:
  "@example-org/*":
    access: $authenticated
    publish: $authenticated
    proxy: ""  # Internal packages only — no npm proxy

  "**":
    access: $authenticated
    publish: $authenticated
    proxy: npmjs  # All other packages proxied from npm

security:
  api:
    jwt:
      sign:
        expiresIn: 60d
      verify:
        someProp: [val]
```

---

## Admission Controller Configuration for Deployment Integrity

### OPA Gatekeeper Constraint Template

```yaml
# constraint-template-require-signed-images.yaml
apiVersion: templates.gatekeeper.sh/v1
kind: ConstraintTemplate
metadata:
  name: requiresignedimages
spec:
  crd:
    spec:
      names:
        kind: RequireSignedImages
      validation:
        openAPIV3Schema:
          properties:
            registries:
              type: array
              items:
                type: string
            signerIdentity:
              type: string
  targets:
    - target: admission.k8s.gatekeeper.sh
      rego: |
        package requiresignedimages

        import future.keywords.if
        import future.keywords.in

        violation[{"msg": msg}] if {
            container := input.review.object.spec.containers[_]
            registry_match(container.image)
            not has_valid_signature(container.image)
            msg := sprintf("Container image %v must be signed. See supply chain security policy.", [container.image])
        }

        registry_match(image) if {
            registry := input.parameters.registries[_]
            startswith(image, registry)
        }

        has_valid_signature(image) if {
            annotations := input.review.object.metadata.annotations
            annotations[_] == image
        }
---
# Apply constraint to production namespace
apiVersion: constraints.gatekeeper.sh/v1beta1
kind: RequireSignedImages
metadata:
  name: require-signed-production-images
spec:
  match:
    kinds:
      - apiGroups: [""]
        kinds: ["Pod"]
    namespaces: ["production"]
  parameters:
    registries:
      - "registry.example.com"
    signerIdentity: "https://github.com/example-org"
```

---

## Third-Party Vendor Assessment Process

### Assessment Workflow

**Step 1: Trigger Assessment**

Assessments are triggered by:
- New third-party software vendor onboarding
- Annual review of existing Critical and Important tier vendors
- Disclosed security incident at a vendor
- Significant software version change (major version, architecture change)

**Step 2: Questionnaire Distribution**

Distribute the standardized supply chain security questionnaire (see Framework, TPR-1) through the vendor management platform. Set a response deadline of 30 business days.

**Step 3: Technical Validation**

For Critical tier vendors, supplement questionnaire responses with technical validation:

```bash
# Check OpenSSF Scorecard for open source components
scorecard --repo=github.com/vendor/critical-library \
  --checks=Code-Review,Branch-Protection,Dependency-Update-Tool,Signed-Releases,Token-Permissions

# Check for SBOM availability
# Attempt to fetch SBOM from known locations
curl -sfL "https://api.github.com/repos/vendor/critical-library/releases/latest" | \
  jq '.assets[] | select(.name | contains("sbom"))'

# Check signing of published releases
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/vendor/critical-library:latest 2>/dev/null \
  && echo "SIGNED" || echo "UNSIGNED"

# Check for known vulnerabilities in vendor's software supply chain
grype db update
grype "registry.example.com/vendor/critical-library:latest" \
  --only-fixed
```

**Step 4: Risk Scoring**

Score each vendor on a 0–100 scale across five dimensions:

| Dimension | Weight | Scoring criteria |
|---|---|---|
| SDLC security | 25% | NIST SSDF compliance, code review practices, SAST/DAST |
| SBOM maturity | 20% | SBOM provision, format, completeness, currency |
| Artifact integrity | 20% | Code signing, hash verification, distribution integrity |
| Vulnerability response | 20% | Disclosure process, patch SLA, bug bounty, CVE track record |
| Incident notification | 15% | Contractual notification commitment, demonstrated history |

**Step 5: Remediation and Exceptions**

- **Score >= 70:** Approve onboarding / renewal
- **Score 50–69:** Conditional approval with documented compensating controls and improvement plan
- **Score < 50:** Reject or require significant improvement plan with re-assessment within 90 days

**Step 6: Ongoing Monitoring**

```python
# vendor_monitoring.py — automated daily monitoring
import requests
from datetime import datetime, timezone

class VendorMonitor:
    def check_cve_exposure(self, vendor_sbom: dict) -> list:
        """Check vendor SBOM components against OSV database for new vulnerabilities."""
        new_vulns = []
        for component in vendor_sbom.get("components", []):
            purl = component.get("purl")
            if not purl:
                continue
            response = requests.post(
                "https://api.osv.dev/v1/query",
                json={"package": {"purl": purl}}
            )
            vulns = response.json().get("vulns", [])
            for vuln in vulns:
                if self._is_new_since_last_check(vuln["id"]):
                    new_vulns.append({
                        "vendor": vendor_sbom["metadata"]["component"]["name"],
                        "component": component["name"],
                        "version": component["version"],
                        "vuln_id": vuln["id"],
                        "severity": vuln.get("database_specific", {}).get("severity", "UNKNOWN")
                    })
        return new_vulns
```
