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

> For a complete structured assessment framework including risk tiers, scoring worksheets, continuous monitoring SLAs, and exception management — see the [Open Source Component Assessment Guide](open-source-component-assessment.md).

### OSS-1: Open Source Component Approval

**Control:** New open source dependencies must be evaluated before introduction using the six-dimension assessment framework (maintainer health, security posture, supply chain integrity, license, community, functionality scope). See [Open Source Component Assessment](open-source-component-assessment.md) for the full scoring model and risk tier classification.

Minimum gate criteria for new dependencies:
- **Security posture:** OpenSSF Scorecard score ≥ 6/10 for Tier 1 approval; < 4/10 triggers security engineer review
- **License compatibility:** Auto-approved licenses (MIT, Apache 2.0, BSD) proceed without review; GPL/AGPL require architecture review
- **Maintenance health:** Bus factor = 1 (single maintainer) escalates to Restricted tier regardless of other scores
- **Supply chain integrity:** Binary blobs in source tree trigger automatic escalation

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

---

## AI/ML Model Supply Chain Security

As AI and machine learning models become software dependencies — fetched from model hubs, embedded in application containers, or served as API backends — they introduce a new class of supply chain risk. This section defines controls for the model supply chain: how models are sourced, verified, stored, and served.

### ML-1: Model Provenance and Source Verification

**Control:** AI/ML models used in production must have verifiable provenance: a documented source (training organization, model hub, internal training run), version/commit reference, and ideally a cryptographic attestation or hash binding the model weights to their source.

**Rationale:** Pre-trained models downloaded from public hubs (Hugging Face, TensorFlow Hub, Ollama registry) are analogous to open source packages — they can be backdoored, tampered with in transit, or substituted with malicious versions. Unlike code packages, model weights are opaque; a backdoored model cannot be detected by reading the weights.

**Implementation:**

```python
# Verify model hash before loading (SHA-256 of model weights file)
import hashlib

EXPECTED_HASH = "sha256:a3b4c5d6e7f8..."  # Record from model card or release notes

def verify_model_integrity(model_path: str, expected_hash: str) -> bool:
    sha256 = hashlib.sha256()
    with open(model_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    actual_hash = f"sha256:{sha256.hexdigest()}"
    if actual_hash != expected_hash:
        raise ValueError(
            f"Model integrity check FAILED.\n"
            f"Expected: {expected_hash}\n"
            f"Actual:   {actual_hash}\n"
            "Model may be corrupted or tampered. Do not proceed."
        )
    return True
```

For models downloaded from Hugging Face, pin to a specific commit SHA of the model repository rather than a mutable version tag:

```python
from transformers import AutoModelForSequenceClassification

# Bad: mutable reference (model may change)
model = AutoModelForSequenceClassification.from_pretrained("bert-base-uncased")

# Good: pinned to a specific commit SHA
model = AutoModelForSequenceClassification.from_pretrained(
    "bert-base-uncased",
    revision="86b5e0934494bd15c9632b12f734a8a67f723594"  # Immutable commit reference
)
```

**Maturity:** Standard | **SLSA relevance:** Level 3 (declared materials, verified inputs)

---

### ML-2: Model SBOM (Model Bill of Materials)

**Control:** Each AI/ML model used in production must have a documented model bill of materials capturing: base model identifier and version, fine-tuning dataset references, training framework and version, evaluation results, known limitations, and intended use scope.

**Rationale:** A model SBOM provides the same visibility into the model dependency graph that a code SBOM provides for software packages — enabling vulnerability correlation, regulatory disclosure, and incident response. Emerging standards (CycloneDX 1.5+ supports ML model components as first-class entities).

**Implementation using CycloneDX for ML models:**

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "components": [
    {
      "type": "machine-learning-model",
      "name": "payments-fraud-classifier",
      "version": "2.1.0",
      "description": "Binary classifier for payment fraud detection",
      "modelCard": {
        "modelParameters": {
          "approach": {
            "type": "supervised-classification"
          },
          "task": {
            "type": "binary-classification"
          },
          "architectureFamily": "transformer",
          "modelArchitecture": "bert-base-uncased"
        },
        "quantitativeAnalysis": {
          "performanceMetrics": [
            {
              "type": "AUC-ROC",
              "value": "0.943",
              "slice": "hold-out test set, Q3 2025"
            }
          ]
        },
        "considerations": {
          "limitations": ["Performance degrades for transactions in emerging markets"],
          "ethicalConsiderations": ["Bias evaluation: see model-card.md#fairness"]
        }
      },
      "purl": "pkg:huggingface/org/payments-fraud-classifier@2.1.0",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "a3b4c5d6e7f8..."
        }
      ]
    }
  ]
}
```

**Maturity:** Advanced | **SLSA relevance:** Level 3+ (model as a declared material)

---

### ML-3: Private Model Registry

**Control:** Production models must be stored in a private, access-controlled model registry — not loaded directly from public model hubs at inference time. The registry enforces integrity checks before serving models.

**Rationale:** Loading models from public hubs at inference time creates a runtime dependency on external availability and introduces the risk of model substitution. A private registry provides the same security properties as a private package registry for code: controlled ingress, integrity verification, and access logging.

**Implementation options:**

| Option | Description | Use Case |
|---|---|---|
| Hugging Face Enterprise Hub | Private organization hub with SSO and access controls | Organizations already on Hugging Face |
| MLflow Model Registry | Open source model registry with versioning and access control | Self-hosted; PyTorch/TensorFlow workflows |
| DVC (Data Version Control) with S3 | Git-native model versioning backed by S3 | Teams using DVC for data/model management |
| OCI registry (Docker Hub / ECR / ACR) | Bundle model weights as OCI artifacts alongside container image | Container-native deployment; enables Cosign signing |
| Weights & Biases (W&B) Artifacts | Artifact registry with lineage tracking and access control | Teams using W&B for experiment tracking |

**Bundling models as OCI artifacts (enables Cosign signing):**

```dockerfile
# Package model weights alongside inference service in container
FROM python:3.12-slim AS base

WORKDIR /app
COPY requirements.txt .
RUN pip install --require-hashes -r requirements.txt

# Copy model weights from a content-addressed store (not downloaded at runtime)
COPY --from=model-store:sha256:abc123 /models/fraud-classifier /app/models/fraud-classifier

COPY src/ .
CMD ["python", "serve.py"]
```

The resulting container image is signed with Cosign, meaning both the code and the model weights are covered by the signature and provenance attestation.

**Maturity:** Standard

---

### ML-4: Model Vulnerability Scanning

**Control:** Models must be scanned for known vulnerabilities in their serialization format and for malicious payload embedding before being promoted to the production registry. Unsafe serialization formats must not be used for untrusted model sources.

**Rationale:** Certain model serialization formats (Python pickle, PyTorch `.pt` files saved with `torch.save()`) can embed arbitrary executable Python code. A backdoored model distributed as a pickle file executes malicious code when loaded — analogous to a malicious package executing at install time.

**Unsafe serialization formats to prohibit from untrusted sources:**

| Format | Risk | Safe Alternative |
|---|---|---|
| Python pickle (`.pkl`) | Arbitrary code execution on deserialization | SafeTensors, ONNX |
| PyTorch `.pt` (pickle-based) | Arbitrary code execution on deserialization | SafeTensors (`model.safetensors`) |
| `cloudpickle` | Arbitrary code execution | SafeTensors, ONNX |
| Keras H5 with Lambda layers | Lambda layers can contain arbitrary code | SavedModel format without Lambda layers |

**Implementation — scan with Protect AI ModelScan or equivalent:**

```bash
# ModelScan: detect malicious payloads in model files before loading
pip install modelscan

# Scan a downloaded model before adding it to the registry
modelscan scan -p ./downloaded-model/ --output-format json

# Integrate into CI for models checked into the repository
modelscan scan -p ./models/ \
  --output-format json \
  --output-file modelscan-results.json

# Fail CI if any malicious payload is detected
python -c "
import json, sys
results = json.load(open('modelscan-results.json'))
if results.get('total_issues', 0) > 0:
    print('FAIL: Malicious payload detected in model file')
    sys.exit(1)
print('PASS: No malicious payloads detected')
"
```

**Require SafeTensors format for all model weights from external sources:**

```python
# Enforce SafeTensors loading — no pickle
from safetensors.torch import load_file

# Safe: SafeTensors format cannot execute arbitrary code on load
model_weights = load_file("model.safetensors")

# If loading from Hugging Face, specify use_safetensors=True
from transformers import AutoModelForCausalLM
model = AutoModelForCausalLM.from_pretrained(
    "org/model-name",
    revision="abc123",
    use_safetensors=True  # Refuse to load if SafeTensors not available
)
```

**Maturity:** Standard

---

### ML-5: Model Access Control and Audit Logging

**Control:** Access to production model weights must be subject to the same access controls as production secrets: role-based access, audit logging of all access events, and quarterly access reviews.

**Rationale:** Model weights may encode sensitive information from training data (memorized PII, business logic, proprietary data). They are also a high-value target for intellectual property theft. Access controls and audit logging provide the same benefits as for other sensitive assets.

**Implementation:**

| Control | Implementation |
|---|---|
| RBAC for model registry | Production models accessible only by inference service accounts and authorized ML engineers |
| Service account for inference | Inference service uses a dedicated, least-privilege service account to pull model weights at startup |
| Audit logging | All model registry access (pull, push, delete) logged with principal identity and timestamp |
| Access review | Quarterly review of who can access production model weights |
| Egress control | Inference service containers cannot exfiltrate model weights (egress allowlisting) |

---

### ML-6: Mapping to Traditional Supply Chain Controls

AI/ML model supply chain controls complement — and in some cases extend — the traditional software supply chain controls in this framework:

| Software Supply Chain Control | Model Supply Chain Equivalent |
|---|---|
| DEP-1/DEP-2: Dependency pinning and lockfiles | ML-1: Pin to specific model commit SHA; record hash |
| SBOM-1: SBOM generation | ML-2: Model Bill of Materials (CycloneDX 1.6+ ML model component) |
| REG-1/REG-2: Private registry and access control | ML-3: Private model registry with access controls |
| BUILD-3: Hermetic build inputs | ML-4: SafeTensors-only loading; ModelScan before promotion |
| SIGN-1: Artifact signing | Bundle model in container image and sign the container with Cosign |
| PROV-1: Provenance attestation | Generate SLSA provenance for container images containing model weights |

The goal is a unified supply chain assurance posture: the same integrity guarantees that apply to code packages apply to the models those packages serve.

**Maturity:** Standard

---

### ML-7: Inference-Time Security and Input Validation

**Control:** AI/ML inference endpoints must implement input validation and output filtering controls to prevent prompt injection, adversarial input exploitation, and sensitive data exfiltration through model responses.

**Rationale:** Supply chain integrity guarantees (model provenance, signing, SBOM) ensure that a trustworthy model is deployed — but they do not protect against attacks that exploit the model's behavior at inference time. An authenticated, integrity-verified LLM endpoint is still vulnerable to prompt injection if its inputs are not validated. Inference-time security is the runtime complement to supply chain security.

**Control areas:**

| Threat | Inference-Time Control |
|---|---|
| Prompt injection (direct) | Input validation schema; system prompt isolation; refusal classifiers |
| Prompt injection (indirect) | Treat all user-provided content as untrusted even if retrieved from internal sources; validate RAG retrieval results before including in context |
| Sensitive data exfiltration via output | Output filtering for PII, credentials, and proprietary data patterns before returning model responses to external clients |
| Denial-of-service via adversarial inputs | Input length limits; token budget enforcement; rate limiting on the inference endpoint |
| Model inversion (training data extraction) | Limit model verbatim output; apply differential privacy where model training data is sensitive |
| Tool/function call abuse (agentic models) | Apply explicit tool allowlists and deny-by-default permission models for models with function-calling capabilities; log all tool invocations |

**Implementation — input/output guardrails for LLM endpoints:**

```python
from guardrails import Guard
from guardrails.hub import RestrictToTopic, DetectPII, ValidLength

# Define input guards
input_guard = Guard().use_many(
    ValidLength(min=1, max=4096, on_fail="exception"),
    RestrictToTopic(
        valid_topics=["product_support", "documentation"],
        on_fail="exception"
    )
)

# Define output guards
output_guard = Guard().use_many(
    DetectPII(
        pii_entities=["EMAIL_ADDRESS", "CREDIT_CARD", "SSN"],
        on_fail="fix"  # Redact detected PII from output
    )
)

def handle_inference_request(user_input: str) -> str:
    # Validate input
    validated_input = input_guard.validate(user_input)

    # Run inference
    raw_output = model.generate(validated_input)

    # Filter output
    safe_output = output_guard.validate(raw_output)

    return safe_output
```

**Agentic model tool access manifest (restrict tool access at the framework layer, not prompt layer):**

```yaml
# agent-permissions.yaml
# Explicitly declare which tools are available to each agent role.
# Tools not listed are inaccessible regardless of what the agent's prompts request.
agents:
  - role: code-review-agent
    allowed_tools:
      - read_repository
      - comment_on_pr
      - query_sast_results
    denied_tools:
      - merge_pull_request
      - deploy_to_production
      - modify_pipeline_configuration
      - read_secrets

  - role: release-notes-agent
    allowed_tools:
      - read_git_history
      - read_commit_messages
      - write_release_notes_draft
    denied_tools:
      - merge_pull_request
      - deploy_to_production
      - access_secrets
```

**Maturity:** Standard | **Applies to:** Organizations deploying LLM-powered applications or agentic pipeline tools

---

## Controls Framework Summary

This framework defines supply chain security controls across 13 domains:

| Domain | Controls | Maturity Range |
|--------|----------|----------------|
| Dependency Security (DEP) | DEP-1 through DEP-6 | Foundational → Standard |
| SBOM Generation and Management (SBOM) | SBOM-1 through SBOM-4 | Standard → Advanced |
| Artifact Signing and Verification (SIGN) | SIGN-1 through SIGN-4 | Standard |
| Secure Build Systems (BUILD) | BUILD-1 through BUILD-5 | Standard → Advanced |
| Provenance and Traceability (PROV) | PROV-1 through PROV-2 | Standard |
| SLSA Compliance Controls | Compliance matrix | Foundational → Advanced |
| Third-Party Risk Management (TPR) | TPR-1 through TPR-2 | Standard |
| Open Source Risk Management (OSS) | OSS-1 through OSS-3 | Standard → Advanced |
| Container Image Security (IMG) | IMG-1 through IMG-4 | Foundational → Standard |
| Registry Security (REG) | REG-1 through REG-4 | Foundational → Standard |
| Deployment Integrity Verification (DEPLOY) | DEPLOY-1 through DEPLOY-3 | Standard → Advanced |
| Policy Enforcement (POL) | POL-1 through POL-2 | Standard |
| AI/ML Model Supply Chain (ML) | ML-1 through ML-7 | Standard → Advanced |

**Implementation Sequencing**

For organizations starting from a baseline state:

1. **Foundational (Month 1–2):** DEP-1, DEP-2, DEP-5, SBOM-1, SIGN-1, BUILD-1, REG-1, REG-2, IMG-3, DEPLOY-1
2. **Standard (Month 3–6):** DEP-3, DEP-4, DEP-6, SBOM-2, SBOM-3, SIGN-2, SIGN-3, SIGN-4, BUILD-2, BUILD-3, PROV-1, PROV-2, TPR-1, OSS-1, OSS-2, IMG-1, IMG-2, REG-3, REG-4, DEPLOY-3, POL-1, POL-2
3. **Advanced (Month 6–12):** SBOM-4, BUILD-4, BUILD-5, TPR-2, OSS-3, DEPLOY-2
4. **AI/ML Supplement (when applicable):** ML-1 through ML-7

See the companion [SLSA Level Advancement Guide](slsa-level-advancement.md) for SLSA-specific sequencing.
