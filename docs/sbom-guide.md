# SBOM Format and Tool Selection Guide

A Software Bill of Materials (SBOM) is a structured inventory of all components in a software artifact — libraries, frameworks, operating system packages, and their transitive dependencies. This guide covers the two dominant SBOM formats, the tools that generate them, when to choose each, and how to integrate SBOM generation into a CI/CD pipeline.

---

## Why SBOM Format Matters

An SBOM is only useful if the consuming system — a vulnerability scanner, a policy engine, an auditor's dashboard — can parse and process it. Format choice determines:

- **Interoperability** with downstream tools (Dependency-Track, Grype, OWASP DependencyTrack, FOSSA)
- **Compliance acceptability** (US Executive Order 14028 accepts both CycloneDX and SPDX; EU CRA draft guidance converges on these two formats)
- **Expressiveness** (not all formats support all SBOM data types with equal fidelity)
- **Ecosystem fit** (some formats are better supported in specific tool ecosystems)

---

## Format Comparison: CycloneDX vs SPDX

### CycloneDX

**Maintained by:** OWASP
**Current version:** 1.6
**Formats:** JSON, XML
**Primary use case:** Security-focused SBOM; vulnerability analysis; VEX integration; pipeline enforcement

| Attribute | CycloneDX |
|-----------|-----------|
| License expression | SPDX license expressions (subset) |
| Vulnerability exchange (VEX) | Native — CycloneDX includes VEX as a first-class concept |
| Component types | Libraries, frameworks, containers, firmware, operating systems, devices, files, services |
| Service dependency mapping | Yes — services and endpoints are modeled |
| Composition completeness | Yes — completeness field indicates if SBOM is complete or partial |
| Formulation (build environment) | Yes — buildSystem, trigger, workflow tooling |
| Attestations | Yes — evidence, attestations, claims |
| Tool ecosystem | Syft, Trivy, cdxgen, Dependency-Track (native), OWASP Dependency-Check |
| Compliance acceptance | EO 14028, EU CRA (draft), NTIA minimum elements |
| Maturity | High — well-defined schema, tooling, and governance |

**Best for:** Teams where the primary use case is vulnerability correlation, VEX workflow, and pipeline policy enforcement. Dependency-Track has native CycloneDX support.

---

### SPDX

**Maintained by:** Linux Foundation / SPDX working group
**Current version:** 2.3 / 3.0
**Formats:** JSON, YAML, RDF, tag-value (.spdx), spreadsheet
**Primary use case:** License compliance; legal review; cross-ecosystem sharing

| Attribute | SPDX |
|-----------|------|
| License expression | SPDX license expressions (authoritative — SPDX defines the standard) |
| Vulnerability exchange (VEX) | External — via OpenVEX or separate advisories |
| Component types | Packages, files, snippets |
| Service dependency mapping | Limited in 2.3; improving in 3.0 |
| Composition completeness | Relationship types indicate completeness |
| Formulation (build environment) | Partial — improving in 3.0 |
| Attestations | In-Toto linkage (via SPDX 3.0) |
| Tool ecosystem | Syft, Trivy, FOSSology, FOSSA, Black Duck, SPDX Tools |
| Compliance acceptance | EO 14028, EU CRA (draft), OpenChain, Linux Foundation projects |
| Maturity | High — ISO/IEC 5962:2021 standardized |

**Best for:** Teams where license compliance is the primary driver; open source projects; legal/procurement workflows; organizations already using FOSSA or Black Duck.

---

### Decision Matrix

| Primary Use Case | Recommended Format | Rationale |
|------------------|--------------------|-----------|
| Vulnerability analysis and patching | **CycloneDX** | Native VEX support; Dependency-Track integration |
| License compliance and legal review | **SPDX** | Authoritative license expression standard; legal ecosystem support |
| US government compliance (EO 14028) | Either (both accepted) | Follow agency-specific guidance; default to CycloneDX if vulnerability focus |
| EU Cyber Resilience Act compliance | **CycloneDX** | EU CRA draft guidance leans toward CycloneDX for security SBOM |
| Open source project transparency | **SPDX** | Linux Foundation and OpenChain prefer SPDX |
| Multi-consumer SBOM (both security and legal) | **Generate both** | Use Syft or Trivy to generate CycloneDX and SPDX simultaneously; negligible overhead |
| Container images | **CycloneDX** | OS package + application layer modeling is more complete in CycloneDX |
| Firmware and embedded systems | **CycloneDX 1.5+** | CycloneDX has explicit firmware and device component types |

---

## SBOM Generation Tool Comparison

### Syft (Anchore)

**Type:** Open source
**Language support:** Go, Java (Maven/Gradle), Python, Node.js, Ruby, .NET, PHP, Rust, Swift, Erlang, and more
**Output formats:** CycloneDX JSON/XML, SPDX JSON/tag-value, Syft native JSON
**Container support:** Docker images, OCI images, image layers
**Installation:** Binary, Homebrew, Docker image

```bash
# Generate CycloneDX SBOM from a container image
syft scan myregistry.io/myapp:sha256-abc123 -o cyclonedx-json=sbom.cdx.json

# Generate SPDX SBOM from a container image
syft scan myregistry.io/myapp:sha256-abc123 -o spdx-json=sbom.spdx.json

# Generate SBOM from a directory (for source or build output scanning)
syft scan ./dist -o cyclonedx-json=sbom.cdx.json
```

**Strengths:** Broad language support; active development; integrates well with Grype for vulnerability scanning; supports attestation via Cosign.

**Limitations:** Does not perform vulnerability analysis itself (use Grype for that); SBOM quality depends on lock file availability.

---

### Trivy (Aqua Security)

**Type:** Open source
**Language support:** Go, Java, Python, Node.js, Ruby, .NET, PHP, Rust, C/C++ (conan), and more
**Output formats:** CycloneDX JSON, SPDX JSON, SARIF (for vulnerabilities)
**Container support:** Docker images, OCI images, Kubernetes SBOMs
**Installation:** Binary, Homebrew, Docker image, GitHub Actions

```bash
# Generate CycloneDX SBOM from container image (with embedded vulnerability data)
trivy image --format cyclonedx --output sbom.cdx.json myregistry.io/myapp:sha256-abc123

# Generate SBOM from a filesystem directory
trivy fs --format cyclonedx --output sbom.cdx.json ./src

# Generate SBOM with vulnerability data included
trivy image --format cyclonedx --output sbom.cdx.json --scanners vuln myregistry.io/myapp:latest
```

**Strengths:** Combined SBOM + vulnerability scanning in one tool; Kubernetes cluster scanning; Helm chart support; native GitHub Actions integration.

**Limitations:** Less language depth than Syft for some ecosystems; CycloneDX output is the primary well-supported format.

---

### cdxgen

**Type:** Open source (OWASP project)
**Language support:** Java, Kotlin, Scala, Node.js, Python, Go, .NET, PHP, Ruby, Rust, Dart, Swift, Elixir, Haskell, and more
**Output formats:** CycloneDX JSON (authoritative), SPDX (via conversion)
**Container support:** Docker images, Kubernetes manifests
**Installation:** npm (`npm install -g @cyclonedx/cdxgen`), Docker image

```bash
# Generate CycloneDX SBOM for a Java Maven project
cdxgen -p -t java -o sbom.cdx.json ./myproject

# Generate CycloneDX SBOM for a Node.js project
cdxgen -p -t nodejs -o sbom.cdx.json ./myproject

# Generate SBOM for a container image
cdxgen -t docker -o sbom.cdx.json myregistry.io/myapp:latest
```

**Strengths:** Deepest CycloneDX support (OWASP project); best for polyglot repositories; supports formulation metadata (build environment capture); active OWASP governance.

**Limitations:** Node.js dependency adds overhead; SPDX support is secondary.

---

### Tool Selection Matrix

| Scenario | Recommended Tool | Alternative |
|----------|-----------------|-------------|
| Container image SBOM (primary use) | Syft or Trivy | cdxgen with `-t docker` |
| Polyglot codebase, CycloneDX preferred | cdxgen | Syft |
| Combined SBOM + vulnerability scan | Trivy | Syft + Grype |
| Java / Maven / Gradle deep analysis | cdxgen | Syft |
| GitHub Actions integration | Trivy or Syft | cdxgen |
| Kubernetes cluster SBOM | Trivy | — |
| Cosign SBOM attestation | Syft (native Cosign plugin) | Trivy with attest flag |
| SPDX output as primary requirement | Syft | Trivy |
| Maximum language coverage | cdxgen | Syft |

---

## CI/CD Integration Patterns

### Pattern 1: SBOM at Build Time (Recommended)

Generate the SBOM immediately after building the container image, before pushing to the registry. Attach the SBOM as a Cosign attestation to the image digest.

```yaml
# GitHub Actions — SBOM generation and attestation
- name: Generate SBOM
  run: |
    syft scan ${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }} \
      -o cyclonedx-json=sbom.cdx.json
  env:
    IMAGE_NAME: myregistry.io/myapp

- name: Attest SBOM with Cosign
  run: |
    cosign attest \
      --predicate sbom.cdx.json \
      --type cyclonedx \
      ${{ env.IMAGE_NAME }}@${{ steps.build.outputs.digest }}
```

**Why at build time:** The SBOM is generated from the exact artifact that will be deployed. Post-deployment SBOM generation may capture a different version.

---

### Pattern 2: SBOM at Source Analysis (Supplemental)

Generate a source-level SBOM during the build phase, before the container image is assembled. Useful for languages where the source analysis is more complete than image analysis.

```yaml
- name: Generate source SBOM
  run: |
    cdxgen -p -t java -o source-sbom.cdx.json .

- name: Upload source SBOM as artifact
  uses: actions/upload-artifact@v4
  with:
    name: source-sbom
    path: source-sbom.cdx.json
```

---

### Pattern 3: SBOM Verification at Deployment

Verify that a valid SBOM attestation exists for the image being deployed. Block deployment if the attestation is missing or invalid.

```yaml
# Kyverno policy to require SBOM attestation
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-sbom-attestation
spec:
  validationFailureAction: Enforce
  rules:
  - name: check-sbom-attestation
    match:
      any:
      - resources:
          kinds: [Pod]
    verifyImages:
    - imageReferences: ["myregistry.io/*"]
      attestations:
      - predicateType: https://cyclonedx.org/bom
        attestors:
        - entries:
          - keyless:
              subject: "https://github.com/myorg/myrepo/.github/workflows/*.yml@refs/heads/main"
              issuer: "https://token.actions.githubusercontent.com"
```

---

## SBOM Minimum Elements (NTIA / EO 14028)

The US NTIA defines a minimum viable SBOM. Ensure your SBOM generation configuration produces at least these fields for every component.

| Field | Description | CycloneDX Field | SPDX Field |
|-------|-------------|-----------------|------------|
| Supplier name | Entity that distributes the component | `supplier` | `PackageSupplier` |
| Component name | Name as known in the package ecosystem | `name` | `PackageName` |
| Version | Version string | `version` | `PackageVersion` |
| Unique identifier | CPE, PURL, or other unique ID | `purl` | `SPDXID` + `ExternalRef` |
| Dependency relationships | What depends on what | `dependencies` | `Relationship` |
| Author of SBOM data | Who created the SBOM | `metadata.authors` | `PackageSupplier` of SPDX document |
| Timestamp | When the SBOM was created | `metadata.timestamp` | `Created` |

---

## SBOM Distribution and Access Control

Not all SBOMs should be public. Consider the sensitivity of what the SBOM reveals.

| SBOM Consumer | Distribution Method | Access Control |
|---------------|---------------------|----------------|
| Internal vulnerability scanning (Dependency-Track) | Push to internal Dependency-Track instance | Internal network only |
| Customer security review (enterprise contracts) | Provided on request, under NDA | Per-customer access |
| Public transparency (open source projects) | Attach to GitHub release artifacts | Public |
| Regulatory compliance submission | Provide to regulator/auditor | Controlled distribution |
| Cosign attestation in registry | Stored as OCI artifact alongside image | Same as image pull permissions |

**Warning:** A public SBOM exposes your full dependency graph, including versions with known vulnerabilities. If your dependencies are not patched, a public SBOM can be used by an attacker to identify exploitation targets. Ensure your vulnerability remediation cadence is consistent with your SBOM transparency policy.

---

## SBOM Quality Assessment

After generating an SBOM, verify it meets quality standards before using it for compliance or security decisions.

```bash
# Validate a CycloneDX SBOM
cyclonedx validate --input-file sbom.cdx.json --input-format json --input-version v1_6

# Check SBOM completeness using Syft
# Look for components with missing PURLs or versions in the output
syft scan myimage --output cyclonedx-json | jq '.components[] | select(.purl == null or .version == null)'

# Count components by type
cat sbom.cdx.json | jq '.components | group_by(.type) | map({type: .[0].type, count: length})'
```

A high-quality SBOM should have:
- PURL present for >95% of components
- Version string present for all components
- No components with `type: unknown` if the language ecosystem is well-supported
- Dependency relationship graph populated (not just a flat list)

---

## Related Documents

- [Software Supply Chain Security Framework](framework.md) — Full SLSA, SBOM, and signing framework
- [Implementation Guide](implementation.md) — 12-month phased supply chain security rollout
- [Secure Pipeline Templates](../../secure-pipeline-templates/templates/github-actions-secure-pipeline.yml) — GitHub Actions template with integrated SBOM generation
- [NTIA SBOM Minimum Elements](https://www.ntia.doc.gov/report/2021/minimum-elements-software-bill-materials-sbom) — US minimum SBOM requirements
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/) — CycloneDX schema and documentation
- [SPDX Specification](https://spdx.dev/specifications/) — SPDX 2.3 and 3.0 specifications
