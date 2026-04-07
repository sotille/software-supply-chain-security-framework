# SLSA Level-by-Level Advancement Guide

SLSA (Supply Chain Levels for Software Artifacts) is a security framework that provides a graduated set of requirements for securing the software build process. Developed by Google and published as an open specification, SLSA defines four levels of increasing rigor. Each level builds directly on the previous one.

This guide provides a step-by-step implementation path for advancing from SLSA Level 1 through Level 3 (the practical target for most organizations), with coverage of Level 4 requirements for regulated or high-assurance environments. For each level, you will find: what is required, why it matters, toolchain configurations, and how to verify compliance.

---

## SLSA Framework Overview

### The Four Levels

| Level | Name | Core Requirement | Threat Mitigated |
|-------|------|-----------------|-----------------|
| L1 | Documented | Build process is scripted; provenance is generated | Accidental publication of unreviewed builds |
| L2 | Authenticated | Provenance is signed and hosted on a tamper-evident service | Build service compromise; unsigned artifact substitution |
| L3 | Hardened | Build runs on an isolated, ephemeral build service; provenance includes complete build inputs | Compromised build environment; dependency substitution |
| L4 | Two-party review | All source code changes require two-person review; hermetic, reproducible builds | Insider threat; dependency confusion; build tampering |

### SLSA and Artifact Integrity

SLSA attestations are machine-verifiable records answering: **who built this artifact, from what source, using what build system, at what time?**

An attestation is a signed document in SLSA Provenance format:

```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v0.2",
  "subject": [
    {
      "name": "registry.internal/payments/processor",
      "digest": {"sha256": "abc123def456..."}
    }
  ],
  "predicate": {
    "builder": {
      "id": "https://github.com/actions/runner/releases/tag/v2.311.0"
    },
    "buildType": "https://github.com/slsa-framework/slsa-github-generator/container@v1",
    "invocation": {
      "configSource": {
        "uri": "git+https://github.com/org/payments@refs/heads/main",
        "digest": {"sha1": "def456abc123"},
        "entryPoint": ".github/workflows/build.yml"
      }
    },
    "materials": [
      {
        "uri": "git+https://github.com/org/payments@refs/heads/main",
        "digest": {"sha1": "def456abc123"}
      }
    ]
  }
}
```

---

## Level 1: Documented Build Process

### What SLSA L1 Requires

- The build process must be **fully scripted** — no manual steps
- Build provenance must be **generated** (but does not need to be signed or verified)
- The build must be **hosted on a build service** (not a developer's laptop)

### Why L1 Matters

L1 eliminates the most common supply chain failure mode: manually built and published artifacts that cannot be traced back to a source commit. It establishes the foundational audit trail required by all higher levels.

### L1 Implementation Checklist

- [ ] All builds run in a CI/CD pipeline (GitHub Actions, GitLab CI, Jenkins, Azure Pipelines)
- [ ] No production artifacts are built and pushed from developer workstations
- [ ] Pipeline configuration is committed to the repository
- [ ] Build produces a provenance document with: source repo URI, commit SHA, build timestamp, artifact digest
- [ ] Artifact digest (SHA-256) is captured and recorded in pipeline output

### GitHub Actions: L1 Provenance Generation

The SLSA GitHub Generator project provides reusable GitHub Actions workflows that generate SLSA-compliant provenance.

```yaml
# .github/workflows/build-l1.yml
name: Build with SLSA L1 Provenance

on:
  push:
    branches: [main]
  release:
    types: [created]

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    outputs:
      image-digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2

      - name: Build container image
        id: build
        uses: docker/build-push-action@4f58ea79222b3b9dc2c8bbdd6debcef730109a75  # v6.9.0
        with:
          push: true
          tags: registry.internal/${{ github.repository }}:${{ github.sha }}
          labels: |
            org.opencontainers.image.source=${{ github.server_url }}/${{ github.repository }}
            org.opencontainers.image.revision=${{ github.sha }}
            org.opencontainers.image.created=${{ github.event.repository.updated_at }}

      - name: Generate minimal provenance (L1)
        run: |
          cat > provenance.json << EOF
          {
            "buildSystem": "github-actions",
            "workflow": "${{ github.workflow }}",
            "repository": "${{ github.repository }}",
            "commitSHA": "${{ github.sha }}",
            "runId": "${{ github.run_id }}",
            "buildTimestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
            "artifactDigest": "${{ steps.build.outputs.digest }}"
          }
          EOF

      - name: Upload provenance as artifact
        uses: actions/upload-artifact@v4
        with:
          name: provenance
          path: provenance.json
```

### Verification (L1)

At L1, verification is manual — confirm that the artifact digest matches the value recorded in the pipeline run output.

```bash
# Pull the image and get its digest
docker pull registry.internal/payments/processor:sha-abc123
ACTUAL_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' registry.internal/payments/processor:sha-abc123 | cut -d@ -f2)

# Compare to the digest recorded in the pipeline
echo "Actual digest:  $ACTUAL_DIGEST"
echo "Expected digest: sha256:abc123def456..."
```

---

## Level 2: Authenticated Provenance

### What SLSA L2 Requires (adds to L1)

- Provenance must be **signed** using a persistent signing key or ephemeral key bound to a recognized build service identity
- Provenance must be **hosted on a tamper-evident service** (a transparency log like Rekor, or an attestation store with integrity guarantees)
- The **build service generates and signs the provenance** — it is not self-attestation by the build script

### Why L2 Matters

L2 prevents an attacker who has compromised a developer account or CI/CD secret from injecting a malicious artifact and fabricating provenance. Because provenance is signed by the build service's identity (not a developer key), a compromised developer cannot forge it.

### L2 Implementation: GitHub Actions + SLSA Generator

The `slsa-framework/slsa-github-generator` is the reference implementation for GitHub Actions. It uses GitHub's OIDC token to bind provenance to the specific workflow run — no persistent signing key required.

```yaml
# .github/workflows/build-l2.yml
name: Build with SLSA L2 Provenance

on:
  push:
    branches: [main]
  release:
    types: [created]

permissions:
  contents: read
  id-token: write    # Required for OIDC-based signing
  packages: write    # Push to container registry

jobs:
  build:
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
    with:
      image: registry.internal/payments/processor
      digest: ${{ needs.build-image.outputs.digest }}
    secrets:
      registry-username: ${{ github.actor }}
      registry-password: ${{ secrets.GITHUB_TOKEN }}
```

Or with a custom build + SLSA generator in the same workflow:

```yaml
name: Build and Attest (L2)

on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: read
  packages: write
  attestations: write  # Required for GitHub artifact attestations

jobs:
  build-and-attest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - name: Build image
        id: build
        uses: docker/build-push-action@4f58ea79222b3b9dc2c8bbdd6debcef730109a75
        with:
          push: true
          tags: ghcr.io/${{ github.repository }}:${{ github.sha }}

      # GitHub's native attestation — stores in Sigstore Rekor (SLSA L2)
      - name: Attest build provenance
        uses: actions/attest-build-provenance@v2
        with:
          subject-name: ghcr.io/${{ github.repository }}
          subject-digest: ${{ steps.build.outputs.digest }}
          push-to-registry: true
```

### L2 Implementation: GitLab CI + Cosign

```yaml
# .gitlab-ci.yml
build-and-sign:
  stage: build
  image: docker:latest
  services:
    - docker:dind
  variables:
    REGISTRY: registry.internal
    IMAGE: $REGISTRY/payments/processor
  script:
    - docker build -t $IMAGE:$CI_COMMIT_SHA .
    - docker push $IMAGE:$CI_COMMIT_SHA
    - DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' $IMAGE:$CI_COMMIT_SHA | cut -d@ -f2)
    - echo "DIGEST=$DIGEST" >> build.env

    # Sign with Cosign keyless (OIDC-based — SLSA L2)
    - cosign sign --yes $IMAGE@$DIGEST
    # Generate and attach SLSA provenance attestation
    - |
      cosign attest --yes \
        --type slsaprovenance \
        --predicate <(cat <<EOF
        {
          "buildType": "https://gitlab.com/gitlab-org/gitlab-runner@v${CI_RUNNER_VERSION}",
          "builder": {"id": "https://gitlab.com/$CI_PROJECT_PATH/-/pipelines/$CI_PIPELINE_ID"},
          "invocation": {
            "configSource": {
              "uri": "git+https://gitlab.com/$CI_PROJECT_PATH@$CI_DEFAULT_BRANCH",
              "digest": {"sha1": "$CI_COMMIT_SHA"},
              "entryPoint": ".gitlab-ci.yml"
            }
          },
          "materials": [{"uri": "git+https://gitlab.com/$CI_PROJECT_PATH", "digest": {"sha1": "$CI_COMMIT_SHA"}}]
        }
        EOF
        ) \
        $IMAGE@$DIGEST
  artifacts:
    reports:
      dotenv: build.env
```

### L2 Verification

```bash
# Verify the container image signature (Cosign keyless)
cosign verify \
  --certificate-identity-regexp "https://github.com/org/payments/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  registry.internal/payments/processor@sha256:abc123def456

# Verify the SLSA provenance attestation
cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity-regexp "https://github.com/org/payments/.*" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  registry.internal/payments/processor@sha256:abc123def456 \
  | jq '.payload | @base64d | fromjson | .predicate'

# Kubernetes admission: enforce signed images (Kyverno policy)
cat <<EOF | kubectl apply -f -
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: Enforce
  background: false
  rules:
    - name: verify-slsa-provenance
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production, payments, auth]
      verifyImages:
        - imageReferences:
            - "registry.internal/*"
          attestors:
            - entries:
                - keyless:
                    subject: "https://github.com/org/*"
                    issuer: "https://token.actions.githubusercontent.com"
                    rekor:
                      url: https://rekor.sigstore.dev
          attestations:
            - predicateType: https://slsa.dev/provenance/v0.2
              conditions:
                - all:
                    - key: "{{ predicate.builder.id }}"
                      operator: StartsWith
                      value: "https://github.com/actions/runner"
EOF
```

---

## Level 3: Hardened Build Environment

### What SLSA L3 Requires (adds to L2)

- The **build is run on a hardened, isolated build environment** — specifically, the build environment is not accessible to the source code owner; it cannot be influenced by developers at build time
- **Ephemeral build environment**: each build gets a fresh environment with no persistence from previous builds
- **Provenance includes all build inputs**: complete list of dependencies used, not just source
- The **build service is hosted on infrastructure not accessible to the build definition authors**

SLSA L3 is the practical target for most production-grade CI/CD pipelines. It defeats the scenario where an attacker with write access to the repository injects malicious steps into the build.

### Why L3 Matters

At L2, a developer with push access to the repository could modify the build workflow to inject malicious steps. At L3, the build service is independent of the source repository — it is not possible for the person writing the code to also control the build infrastructure that signs the provenance.

### L3 Implementation: GitHub Actions Ephemeral Runners

GitHub's hosted runners are ephemeral (each job gets a fresh VM) and are controlled by GitHub infrastructure, not the repository owner. This satisfies the L3 "isolated build environment" requirement when used with the SLSA GitHub Generator.

```yaml
# .github/workflows/build-l3.yml
# Uses slsa-github-generator which enforces L3 controls:
# - Runs on GitHub's infrastructure (not self-hosted by the repo owner)
# - Each build gets an ephemeral runner
# - Provenance is generated and signed by the generator's identity (not the repo's)
# - Rekor transparency log entry is created

name: Build with SLSA L3 Provenance

on:
  push:
    branches: [main]
  release:
    types: [created]

jobs:
  # Step 1: Build the image (in repo-controlled workflow)
  build-image:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    outputs:
      image: ${{ steps.build.outputs.image }}
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - name: Log in to registry
        uses: docker/login-action@9780b0c442fbb1117ed29e0efdff1e18412f7567
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build and push
        id: build
        uses: docker/build-push-action@4f58ea79222b3b9dc2c8bbdd6debcef730109a75
        with:
          push: true
          tags: ghcr.io/${{ github.repository_owner }}/payments-processor:${{ github.sha }}

      - name: Output digest
        id: digest
        run: echo "digest=${{ steps.build.outputs.digest }}" >> "$GITHUB_OUTPUT"

  # Step 2: SLSA provenance generation (runs on SLSA Generator's infrastructure)
  # This job is called from slsa-github-generator — repo owner cannot modify it
  provenance:
    needs: [build-image]
    permissions:
      actions: read
      id-token: write
      packages: write
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
    with:
      image: ghcr.io/${{ github.repository_owner }}/payments-processor
      digest: ${{ needs.build-image.outputs.digest }}
    secrets:
      registry-username: ${{ github.actor }}
      registry-password: ${{ secrets.GITHUB_TOKEN }}
```

### L3 Verification: Full Provenance Audit

```bash
# Install slsa-verifier
go install github.com/slsa-framework/slsa-verifier/v2/cli/slsa-verifier@latest

# Verify container image provenance (SLSA L3)
slsa-verifier verify-image \
  ghcr.io/org/payments-processor@sha256:abc123def456 \
  --source-uri github.com/org/payments \
  --source-branch main \
  --builder-id https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.0.0

# Verify binary artifact provenance (for Go, Python packages, etc.)
slsa-verifier verify-artifact \
  payments-processor-linux-amd64 \
  --provenance-path payments-processor-linux-amd64.intoto.jsonl \
  --source-uri github.com/org/payments \
  --source-branch main
```

### L3 Self-Hosted Runner Requirements

If your organization requires self-hosted runners (air-gapped environments, custom hardware), achieve L3 isolation through:

1. **Runner infrastructure managed by a separate team** from the developers using the runners
2. **Runners in an isolated network segment** with no persistent storage between jobs
3. **No shared runner secrets** between jobs or repositories
4. **Runner provisioning is automated** and runners are terminated after each job

```hcl
# Terraform: ephemeral self-hosted runner on AWS (SLSA L3 compatible)
resource "aws_autoscaling_group" "github_runner" {
  name                = "github-runner-ephemeral"
  min_size            = 0
  max_size            = 20
  desired_capacity    = 0
  vpc_zone_identifier = var.private_subnet_ids

  launch_template {
    id      = aws_launch_template.runner.id
    version = "$Latest"
  }

  # Scale up when GitHub Actions jobs are queued
  # Scale to zero when idle (no persistent runners)
  tag {
    key                 = "RunnerTerminationPolicy"
    value               = "after-job-completion"
    propagate_at_launch = true
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_launch_template" "runner" {
  name = "github-runner-l3-hardened"

  # No persistent root volume — new EBS on each launch
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 40
      delete_on_termination = true  # Ephemeral
      encrypted             = true
      kms_key_id            = var.runner_kms_key_arn
    }
  }

  # Metadata service v2 (IMDSv2) — prevents SSRF attacks on EC2 metadata
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"  # IMDSv2
    http_put_response_hop_limit = 1
  }

  # Egress to GitHub Actions API and tool servers only (no arbitrary internet)
  network_interfaces {
    security_groups = [aws_security_group.runner_restricted.id]
  }

  user_data = base64encode(templatefile("${path.module}/runner-init.sh", {
    github_org   = var.github_org
    runner_token = var.runner_registration_token
  }))
}
```

---

## Level 4: Two-Party Review and Reproducible Builds

### What SLSA L4 Requires (adds to L3)

- All **source code changes require review by at least two authorized persons** (four-eyes principle); the author's review does not count
- **Build is hermetic**: all build inputs are declared and no network access is permitted during the build (all dependencies fetched before build execution begins)
- **Build is reproducible**: given the same inputs, the build produces bit-for-bit identical output (deterministic builds)

### Why L4 Matters

L4 specifically mitigates insider threats: a single compromised or malicious maintainer cannot introduce supply chain malicious code that reaches production, because a second authorized reviewer must approve every change. Hermetic builds ensure that even if the build machine has network access, the build itself cannot fetch unexpected dependencies.

### L4 Implementation: Source Requirements

```yaml
# GitHub: Enforce two-reviewer requirement via CODEOWNERS + branch protection

# .github/CODEOWNERS
# Require two code owners for all files
* @org/security-leads @org/platform-leads

# All CI configuration requires security-platform review
.github/workflows/ @org/security-platform-team
Dockerfile @org/security-platform-team
go.sum @org/security-leads

# Branch protection settings (GitHub API or Terraform)
resource "github_branch_protection" "main" {
  repository_id = github_repository.payments.node_id
  pattern       = "main"

  required_pull_request_reviews {
    dismiss_stale_reviews           = true
    require_code_owner_reviews      = true
    required_approving_review_count = 2  # Minimum 2 approvers
    require_last_push_approval      = true  # Author's push must be reviewed
  }

  required_status_checks {
    strict   = true
    contexts = ["build", "slsa-provenance", "security-scan"]
  }

  restrict_pushes {
    push_allowances = []  # No direct push — PR required for all changes
  }
}
```

### L4 Implementation: Hermetic Builds

Hermetic builds require fetching all dependencies before the build starts and blocking network access during the build.

```yaml
# GitHub Actions: Hermetic build pattern
name: Hermetic Build (SLSA L4)

jobs:
  fetch-dependencies:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      # Fetch all dependencies before build — verify against lock file
      - name: Fetch and verify dependencies
        run: |
          go mod download
          go mod verify  # Verify all downloaded modules against go.sum
          # Cache verified dependencies
      - uses: actions/cache/save@v4
        with:
          path: ~/go/pkg/mod
          key: deps-${{ hashFiles('go.sum') }}

  build-hermetic:
    needs: fetch-dependencies
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683

      - uses: actions/cache/restore@v4
        with:
          path: ~/go/pkg/mod
          key: deps-${{ hashFiles('go.sum') }}
          fail-on-cache-miss: true  # Build fails if dependencies weren't pre-fetched

      # Build with network disabled — all deps must be in cache
      - name: Build without network access
        run: |
          GOFLAGS="-mod=mod" GONOSUMCHECK="*" GOFLAGS="-mod=vendor" \
          go build -v ./...
        env:
          GOPROXY: "off"        # No network fetching during build
          GONOSUMDB: "*"
          GOFLAGS: "-mod=vendor"
```

### L4 Verification: Reproducible Build Check

```bash
#!/usr/bin/env bash
# verify-reproducible-build.sh
# Build the same commit twice and compare digests

set -euo pipefail

REPO="git+https://github.com/org/payments"
COMMIT="$1"

echo "Building commit $COMMIT twice to verify reproducibility..."

# Build 1
docker build \
  --label "org.opencontainers.image.revision=$COMMIT" \
  --tag payments-build-1:test \
  .
DIGEST_1=$(docker inspect --format='{{index .Id}}' payments-build-1:test)

# Clean build environment
docker system prune -f

# Build 2 (identical inputs)
docker build \
  --label "org.opencontainers.image.revision=$COMMIT" \
  --tag payments-build-2:test \
  .
DIGEST_2=$(docker inspect --format='{{index .Id}}' payments-build-2:test)

if [ "$DIGEST_1" = "$DIGEST_2" ]; then
  echo "PASS: Build is reproducible ($DIGEST_1)"
  exit 0
else
  echo "FAIL: Build is NOT reproducible"
  echo "  Build 1: $DIGEST_1"
  echo "  Build 2: $DIGEST_2"
  exit 1
fi
```

---

## SLSA Level Advancement Decision Guide

Use this decision matrix to determine which level to target and sequence your work:

```
Where are you today?
│
├─ Builds happen on developer laptops or have manual steps
│   └─ Target: SLSA L1
│       Actions: Move all builds to CI; script every step; capture artifact digest
│
├─ Builds are in CI but provenance is not signed
│   └─ Target: SLSA L2
│       Actions: Add Cosign keyless signing; deploy SLSA GitHub Generator;
│                store attestations in Rekor; enforce signature verification at deploy time
│
├─ Provenance is signed but runners are self-hosted and persistent
│   └─ Target: SLSA L3
│       Actions: Move to ephemeral runners (GitHub hosted or auto-scaling self-hosted);
│                ensure build infrastructure is managed independently of repo owners;
│                add full build input tracking to provenance
│
└─ SLSA L3 achieved; high-assurance or regulated environment
    └─ Target: SLSA L4
        Actions: Enforce 2-person review (branch protection + CODEOWNERS);
                 implement hermetic builds (GOPROXY=off, vendor mode, pre-fetched deps);
                 validate build reproducibility in CI
```

## Compliance Mapping

| SLSA Level | Regulatory Relevance |
|-----------|---------------------|
| L1 | EO 14028 Section 4(e)(vi) — "maintain accurate and up to date data" on components; NIST SSDF PW.4 |
| L2 | EU Cyber Resilience Act — artifact integrity and provenance; NIST SSDF RV.1; SLSA producer requirement for federal software suppliers |
| L3 | FedRAMP High — SA-12, SR-3, SR-4; PCI-DSS v4 Req 6.3.2 (automated integrity checking); SOC 2 CC9.2 |
| L4 | High-assurance environments (national security systems); CMMC Level 2+ SA-12(3) |

## Related Documents

- [Framework: SLSA and Artifact Provenance](framework.md) — Conceptual overview of SLSA in the supply chain security model
- [SBOM Guide](sbom-guide.md) — Generating and managing Software Bill of Materials alongside SLSA attestations
- [VEX and SBOM Lifecycle](vex-and-sbom-lifecycle.md) — Managing SLSA attestations across artifact lifecycle
- [Incident Response Playbook](incident-response-playbook.md) — Response procedures when SLSA verification fails in production
- [Secure Pipeline Templates: Artifact Signing](../../secure-pipeline-templates/docs/framework.md) — Stage 8: Cosign signing integration in pipeline templates
- [Secure CI/CD: Build Environment Security](../../secure-ci-cd-reference-architecture/docs/architecture.md) — Runner architecture for SLSA L3 compliance
