# Software Supply Chain Security Controls Framework

## Table of Contents

- [Framework Overview](#framework-overview)
- [Dependency Security](#dependency-security)
- [SBOM Generation and Management](#sbom-generation-and-management)
- [Artifact Signing and Verification](#artifact-signing-and-verification)
- [Secure Build Systems](#secure-build-systems)
- [Provenance and Traceability](#provenance-and-traceability)
- [SLSA Compliance Controls](#slsa-compliance-controls)
- [Third-Party Risk Management](#third-party-risk-management)
- [Open Source Risk Management](#open-source-risk-management)
- [Container Image Security](#container-image-security)
- [Registry Security](#registry-security)
- [Deployment Integrity Verification](#deployment-integrity-verification)
- [Policy Enforcement](#policy-enforcement)

---

## Framework Overview

This controls framework defines the specific security controls required at each layer of the software supply chain. Controls are organized by domain and mapped to SLSA levels, NIST SSDF practices, and relevant regulatory requirements.

### Control Maturity Levels

| Level | Description |
|---|---|
| **Foundational** | Basic controls that should be in place for all organizations; prerequisite for higher maturity |
| **Standard** | Controls representing current industry standard practice; required for SLSA 2–3 |
| **Advanced** | Controls representing best-in-class practice; required for SLSA 4 and highest-assurance environments |

---

## Dependency Security

### DEP-1: Dependency Pinning

**Control:** All dependencies must be pinned to specific versions. Ranges (e.g., `^1.2.0`, `>=1.0`) in production configurations are prohibited.

**Rationale:** Unpinned dependencies allow automatic uptake of new versions that may contain vulnerabilities or malicious code. Pinning ensures that the dependency set is explicit, reviewable, and subject to intentional update decisions.

**Implementation:**

```toml
# Bad: unpinned (pyproject.toml)
dependencies = [
  "requests>=2.28.0",
  "cryptography"
]

# Good: pinned
dependencies = [
  "requests==2.31.0",
  "cryptography==42.0.5"
]
```

**Maturity:** Foundational | **SLSA relevance:** Level 3 (declared materials)

### DEP-2: Lockfile Enforcement

**Control:** All projects must maintain dependency lockfiles (package-lock.json, poetry.lock, Pipfile.lock, go.sum, Cargo.lock). CI builds must use lockfiles exclusively and fail if the lockfile does not match the dependency manifest.

**Rationale:** Lockfiles record the exact resolved dependency graph with cryptographic hashes, ensuring that every build uses identical dependencies regardless of when or where it runs.

**Implementation:**

```yaml
# npm: enforce lockfile use in CI
- name: Install dependencies
  run: npm ci  # Uses package-lock.json; fails if not up to date
  # Never use 'npm install' in CI — it may update the lockfile

# Python/pip: use hash-verified installs
- name: Install dependencies
  run: pip install --require-hashes -r requirements.txt
```

**Maturity:** Foundational | **SLSA relevance:** Level 3

### DEP-3: Hash Verification of Dependencies

**Control:** All dependency downloads must be verified against their expected cryptographic hashes before use.

**Implementation for pip:**
```
# requirements.txt with hashes
requests==2.31.0 \
    --hash=sha256:58cd2187423d77b898475b693456feff0f85a28f40e6aee9e281a2f6ad574fde \
    --hash=sha256:942c5a758f98d790eaed1a29cb6eefc7ffb0d1cf7af05c3d2791656dbd6ad1e1
```

**Maturity:** Standard

### DEP-4: Private Artifact Mirror

**Control:** All external package registry traffic must be routed through an organization-controlled private mirror. Direct consumption from public registries (npm, PyPI, Maven Central, Docker Hub) is prohibited in production build pipelines.

**Rationale:** A private mirror provides: (a) the ability to scan packages before they are used, (b) defense against registry availability issues, (c) prevention of dependency confusion attacks through namespace reservation, (d) an audit trail of all consumed packages.

**Implementation (Nexus Repository or JFrog Artifactory):**

```xml
<!-- Maven settings.xml: use private mirror -->
<settings>
  <mirrors>
    <mirror>
      <id>internal-mirror</id>
      <mirrorOf>*</mirrorOf>
      <url>https://nexus.example.com/repository/maven-proxy/</url>
    </mirror>
  </mirrors>
</settings>
```

**Maturity:** Standard | **SLSA relevance:** Level 3

### DEP-5: Automated Dependency Vulnerability Scanning

**Control:** All dependencies must be scanned against known vulnerability databases on every CI build and on a scheduled basis (minimum daily) for repositories with active deployments.

**Implementation:**
```yaml
# Grype scan in CI
- name: Scan dependencies for vulnerabilities
  uses: anchore/scan-action@v3
  with:
    path: "."
    fail-build: true
    severity-cutoff: critical
    output-format: sarif

- name: Upload SARIF results
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

**Maturity:** Foundational

### DEP-6: Dependency Update Policy

**Control:** All dependencies with known vulnerabilities rated CRITICAL must be updated within 7 calendar days of vulnerability disclosure. HIGH vulnerabilities must be updated within 30 days. A formal exception process must exist for cases where updating is not immediately feasible.

**Tooling:** Dependabot, Renovate Bot, Snyk for automated pull request generation.

**Maturity:** Standard

---

## SBOM Generation and Management

### SBOM-1: SBOM Generation for All Production Artifacts

**Control:** An SBOM must be generated for every artifact destined for production deployment. The SBOM must be generated at build time, not inferred from source manifests.

**Rationale:** Build-time SBOM generation captures the actual dependency graph resolved by the build system, including transitive dependencies that may not be visible from manifests alone.

**Implementation:**
```bash
# Generate SBOM for container image using Syft
syft registry.example.com/payment-service:sha256-abc123... \
  -o cyclonedx-json \
  --file payment-service-sbom.json

# Generate SBOM for JAR using cdxgen
cdxgen -t java -o payment-service-sbom.json .
```

**Maturity:** Standard

### SBOM-2: SBOM Attestation and Distribution

**Control:** SBOMs must be cryptographically attested (signed) and co-located with the artifact they describe. SBOMs stored separately from their artifacts are not sufficient — the link between SBOM and artifact must be verifiable.

**Implementation:**
```bash
# Attach SBOM as a signed attestation using Cosign
cosign attest --yes \
  --predicate payment-service-sbom.json \
  --type cyclonedx \
  registry.example.com/payment-service@sha256:abc123...

# Verify SBOM attestation
cosign verify-attestation \
  --type cyclonedx \
  --certificate-identity "https://github.com/example-org/payment-service/.github/workflows/build.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  registry.example.com/payment-service@sha256:abc123...
```

**Maturity:** Standard

### SBOM-3: SBOM Centralized Management

**Control:** All SBOMs for production artifacts must be ingested into a centralized SBOM management platform (e.g., Dependency-Track) that supports:
- Continuous vulnerability matching against OSV, NVD, and GHSA databases
- License compliance analysis
- Policy-based alerting when new vulnerabilities affect an existing deployment
- Drill-down from vulnerability to affected deployments to affected services

**Maturity:** Standard

### SBOM-4: SBOM Completeness Validation

**Control:** SBOM completeness must be validated before acceptance. An SBOM that covers less than 95% of identified components (as determined by independent scanning) is considered incomplete and must trigger remediation.

**Maturity:** Advanced

---

## Artifact Signing and Verification

### SIGN-1: All Production Artifacts Must Be Signed

**Control:** Every artifact (container image, binary, package) deployed to production must be cryptographically signed. Unsigned artifacts must be blocked from production deployment.

**Implementation:** Cosign (keyless via Sigstore) or Notary v2 for OCI artifacts. GPG or PGP for package archives (Maven, npm tarballs).

**Maturity:** Standard

### SIGN-2: Signing Must Be Integrated Into CI, Not Developer Workstations

**Control:** Artifact signing must be performed by the CI/CD system, not by individual developer workstations. Signing keys or ephemeral certificates must be managed by the CI platform.

**Rationale:** Developer workstation signing creates key management and trust chain issues. CI-based signing ensures that only artifacts built through the authorized pipeline can be signed with the authorized identity.

**Maturity:** Standard

### SIGN-3: Signing Events Must Be Recorded in a Transparency Log

**Control:** All signing events must be recorded in a tamper-evident transparency log (Rekor or equivalent). This enables retrospective audit and detection of unauthorized signing.

**Maturity:** Standard

### SIGN-4: Signature Verification Must Occur at Deployment

**Control:** Artifact signature verification must occur at the point of deployment, not only at build time. Admission control policies must reject unsigned or invalidly signed artifacts.

**Maturity:** Standard

---

## Secure Build Systems

### BUILD-1: Isolated Build Environments

**Control:** Every CI build must run in an isolated environment that is provisioned fresh for each build and destroyed afterward. No persistent state may be shared between builds.

**Rationale:** Persistent build environments are vulnerable to environment poisoning — malicious code or compromised tools introduced by one build can affect subsequent builds.

**Implementation:**
- GitHub Actions: use ephemeral, hosted runners (not self-hosted persistent runners unless specifically hardened)
- Self-hosted runners: use ephemeral runner configuration (one-use registration tokens; container or VM-based isolation)
- Jenkins: use Docker agents or Kubernetes ephemeral pods; never run builds on the controller

**Maturity:** Standard | **SLSA relevance:** Level 3

### BUILD-2: Least-Privilege Build Credentials

**Control:** Build systems must operate with least-privilege credentials. Each build must receive only the credentials required for its specific tasks, scoped to the minimum necessary permissions and expiring at build completion.

**Implementation using GitHub Actions OIDC:**
```yaml
jobs:
  build:
    permissions:
      id-token: write  # Required for OIDC token
      contents: read   # Read source only
      packages: write  # Push to GitHub Packages only

    steps:
      - name: Authenticate to registry using OIDC
        uses: docker/login-action@v3
        with:
          registry: registry.example.com
          username: ${{ secrets.REGISTRY_USERNAME }}
          password: ${{ secrets.REGISTRY_PASSWORD }}
          # Better: use OIDC workload identity (no static credentials)
```

**Maturity:** Standard

### BUILD-3: Build Definition Integrity

**Control:** Build pipeline definitions (CI YAML, Makefiles, build scripts) must be subject to the same code review requirements as application code. Changes to build definitions must not take effect without pull request review.

**Rationale:** An attacker who can modify the build definition without review can inject malicious steps into the build process. Treating build definitions as security-critical code prevents this.

**Maturity:** Standard | **SLSA relevance:** Level 2+

### BUILD-4: Hermetic Build Isolation

**Control:** Production builds for Platinum and Gold tier services must be executed in hermetic build environments where network access is blocked after dependency pre-fetch.

**Implementation with Bazel:**
```python
# Bazel BUILD file — all dependencies are declared
java_binary(
    name = "payment-service",
    srcs = glob(["src/main/java/**/*.java"]),
    deps = [
        "@maven//:org_springframework_boot_spring_boot_starter_web",
        "@maven//:org_springframework_boot_spring_boot_starter_security",
    ],
    # Bazel downloads all deps before build; build itself has no network access
)
```

**Maturity:** Advanced | **SLSA relevance:** Level 4

### BUILD-5: Build Reproducibility

**Control:** Builds for critical artifacts should be reproducible. Validate reproducibility by rebuilding from the same source inputs and comparing output digests.

**Maturity:** Advanced | **SLSA relevance:** Level 4

---

## Provenance and Traceability

### PROV-1: SLSA Provenance Generation

**Control:** SLSA provenance must be generated for all production artifacts. Target SLSA Level 2 as the minimum, with SLSA Level 3 for Platinum and Gold tier services.

**Implementation (GitHub Actions with SLSA Generator):**
```yaml
jobs:
  build:
    outputs:
      digest: ${{ steps.build.outputs.digest }}
    steps:
      - name: Build container image
        id: build
        run: |
          docker build -t registry.example.com/payment-service:$GITHUB_SHA .
          DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' registry.example.com/payment-service:$GITHUB_SHA | cut -d@ -f2)
          echo "digest=$DIGEST" >> $GITHUB_OUTPUT

  provenance:
    needs: build
    permissions:
      id-token: write
      contents: read
      actions: read
    uses: slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@v2.0.0
    with:
      image: registry.example.com/payment-service
      digest: ${{ needs.build.outputs.digest }}
```

**Maturity:** Standard

### PROV-2: Provenance Verification at Deployment

**Control:** Provenance attestations must be verified at deployment time. Artifacts without valid provenance from an authorized build system must be blocked from production.

**Maturity:** Standard

---

## SLSA Compliance Controls

### SLSA compliance control mapping by level:

| Control | SLSA 1 | SLSA 2 | SLSA 3 | SLSA 4 |
|---|---|---|---|---|
| Build provenance generated | Required | Required | Required | Required |
| Provenance signed | Not required | Required | Required | Required |
| Hosted build service | Not required | Required | Required | Required |
| Isolated build environment | Not required | Not required | Required | Required |
| Hermetic build | Not required | Not required | Not required | Required |
| Reproducible build | Not required | Not required | Not required | Required |
| Two-person review | Not required | Not required | Not required | Required |
| Non-falsifiable provenance | Not required | Not required | Required | Required |

---

## Third-Party Risk Management

### TPR-1: Software Vendor Security Assessment

**Control:** All third-party software vendors must complete a supply chain security assessment before onboarding and annually thereafter. The assessment must cover:

- SBOM provision capability
- Secure software development lifecycle practices
- Incident notification commitments (vulnerability and breach)
- Code signing practices
- Build system security practices

**Assessment questionnaire areas:**

| Area | Key Questions |
|---|---|
| **SDLC** | Do you follow NIST SSDF or equivalent? Do you conduct code reviews? Do you use SAST/DAST? |
| **SBOM** | Do you generate and provide SBOMs with your software? In what format? How are SBOMs kept current? |
| **Signing** | Do you sign your software artifacts? What signing infrastructure do you use? How are signing keys protected? |
| **Vulnerability management** | What is your vulnerability disclosure process? What SLA do you commit to for critical patches? Do you operate a bug bounty? |
| **Build security** | Is your build infrastructure isolated? Do you use ephemeral build environments? How are build credentials protected? |
| **Incident notification** | Will you notify us within 24 hours of a confirmed supply chain compromise? How? |

**Maturity:** Standard

### TPR-2: Vendor Tiering and Monitoring

**Control:** Third-party software vendors must be tiered based on the criticality of their software to the organization's operations. Higher-tier vendors receive more frequent assessment and proactive monitoring.

| Tier | Criteria | Assessment frequency | Monitoring |
|---|---|---|---|
| **Critical** | Software in critical path of revenue or safety | Annual full assessment + continuous monitoring | CVE alerting, breach notifications, SBOM updates |
| **Important** | Business application software | Annual assessment | CVE alerting, breach notifications |
| **Standard** | Supporting tooling | Biennial assessment | CVE alerting |
| **Low** | Development tools, non-production | Ad hoc | None |

**Maturity:** Standard

---

## Open Source Risk Management

### OSS-1: Open Source Component Approval

**Control:** New open source dependencies must be evaluated before introduction. Evaluation criteria include:

- **Security posture:** OpenSSF Scorecard score (minimum 6/10 for production use), recent vulnerability history, responsive maintainership
- **License compatibility:** License must be compatible with the organization's software distribution model
- **Maintenance health:** Active maintenance, recent commits, multiple maintainers, defined governance
- **Dependency footprint:** Transitive dependency count and quality

**Tooling:** OpenSSF Scorecard, Socket.dev, Phylum, Snyk Open Source.

**Maturity:** Standard

### OSS-2: License Compliance Tracking

**Control:** All open source licenses in the dependency tree must be tracked. Licenses that are incompatible with the organization's software distribution model (e.g., AGPL for proprietary SaaS products) must be identified and either removed or subject to legal review.

**Implementation:** FOSSA, Black Duck, or REUSE compliance tooling integrated into CI.

**Maturity:** Standard

### OSS-3: Maintainer Health Monitoring

**Control:** Critical open source dependencies (top 20 by usage or direct dependency of critical services) must be monitored for maintainer health degradation signals:
- Single maintainer with no succession plan
- Decline in commit activity
- Transfer of repository to unknown entity
- Public statements of project abandonment
- CVE response time degradation

**Maturity:** Advanced

---

## Container Image Security

### IMG-1: Approved Base Image Policy

**Control:** All container images must be built from a curated list of approved base images. Building from arbitrary base images (e.g., pulling directly from Docker Hub without review) is prohibited.

**Approved base image criteria:**
- Published by a known, trusted source (official Docker Library images, distroless, organization-internal base images)
- Regularly updated with security patches
- Scanned for vulnerabilities before approval
- Versioned with immutable tags (no `latest`)

**Maturity:** Standard

### IMG-2: Minimal Base Images

**Control:** Production container images must use minimal base images (Alpine, distroless, scratch) to reduce attack surface. Images must not include development tools, package managers, or shells in the final production image.

**Multi-stage build pattern:**
```dockerfile
# Build stage: includes build tools
FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn package -DskipTests

# Runtime stage: minimal image, no build tools
FROM gcr.io/distroless/java21-debian12:nonroot
COPY --from=builder /app/target/payment-service.jar /app/payment-service.jar
USER nonroot:nonroot
ENTRYPOINT ["java", "-jar", "/app/payment-service.jar"]
```

**Maturity:** Standard

### IMG-3: No Root in Containers

**Control:** Production container images must not run as root (UID 0). The USER instruction must specify a non-root user. Admission control must enforce non-root execution.

**Maturity:** Foundational

### IMG-4: Image Signing

**Control:** All container images must be signed using Cosign before being promoted beyond the build stage. See SIGN-1.

**Maturity:** Standard

---

## Registry Security

### REG-1: Registry Access Control

**Control:** Artifact registries must enforce strict access control:
- Push access limited to authorized CI/CD service accounts only
- Pull access limited to authorized consumers (cluster service accounts, defined individuals)
- No public access to internal registries
- All access logged with actor identity

**Maturity:** Foundational

### REG-2: Immutable Tags

**Control:** Published artifact tags must be immutable — once published, a tag cannot be overwritten. This prevents an attacker (or an insider) from replacing a vetted artifact with a malicious one without detection.

**Implementation:**
- Docker Hub: use digest references (`image@sha256:...`) not mutable tags
- Harbor: enable content trust and immutable tags at the project level
- AWS ECR: enable image tag mutability policy = IMMUTABLE

**Maturity:** Standard

### REG-3: Registry Vulnerability Scanning

**Control:** Registries must scan all images on push and on a scheduled basis (minimum daily). Images with critical vulnerabilities must trigger alerts and (for newly pushed images) may be blocked.

**Maturity:** Standard

### REG-4: Private Registry with External Package Proxying

**Control:** All external package dependencies must be pulled through the organization's private registry acting as a proxy/mirror. Direct internet access to public registries must be blocked from CI build environments.

**Maturity:** Standard

---

## Deployment Integrity Verification

### DEPLOY-1: Signature Verification Before Deployment

**Control:** Container image signatures must be verified before admission to any cluster namespace serving production traffic. Images that fail signature verification must be rejected.

**Maturity:** Standard

### DEPLOY-2: Provenance-Based Admission Control

**Control:** Production namespaces must enforce provenance-based admission control: only images with valid SLSA provenance from authorized build systems may be admitted.

**Maturity:** Advanced

### DEPLOY-3: SBOM-Based Vulnerability Gate

**Control:** Deployments must be blocked if the artifact's SBOM contains components with unmitigated critical vulnerabilities. An exception process must exist for unavoidable cases.

**Maturity:** Standard

---

## Policy Enforcement

### POL-1: OPA/Gatekeeper Policy Enforcement

**Control:** Open Policy Agent (OPA) with Gatekeeper or Kyverno must be deployed in all production clusters to enforce supply chain security policies.

**Example OPA policy — require signed images:**
```rego
package kubernetes.admission

import future.keywords.if
import future.keywords.in

deny[msg] if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not image_is_signed(container.image)
    msg := sprintf("Container image %v is not signed. All production images must be signed with Cosign.", [container.image])
}

image_is_signed(image) if {
    # Check cosign signature annotation set by admission webhook
    annotations := input.request.object.metadata.annotations
    annotations["sigstore.dev/imageSignature"] != null
}
```

**Example Kyverno policy — enforce non-root and image signing:**
```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: supply-chain-baseline
spec:
  validationFailureAction: Enforce
  rules:
    - name: require-non-root
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production]
      validate:
        message: "Containers must not run as root"
        pattern:
          spec:
            containers:
              - securityContext:
                  runAsNonRoot: true
                  allowPrivilegeEscalation: false

    - name: require-approved-base-image
      match:
        any:
          - resources:
              kinds: [Pod]
              namespaces: [production]
      validate:
        message: "Images must use approved base image registries"
        pattern:
          spec:
            containers:
              - image: "registry.example.com/* | gcr.io/distroless/* | cgr.dev/chainguard/*"
```

**Maturity:** Standard

### POL-2: Policy-as-Code Versioning

**Control:** All admission control policies must be stored in version control and deployed through the same review and approval process as application code. Policy changes must not be applied directly to clusters outside of the approved GitOps pipeline.

**Maturity:** Standard
