# Software Supply Chain Security Best Practices

## Table of Contents

- [Source Code Layer](#source-code-layer)
- [Dependencies Layer](#dependencies-layer)
- [Build Layer](#build-layer)
- [Artifacts Layer](#artifacts-layer)
- [Distribution Layer](#distribution-layer)
- [Deployment Layer](#deployment-layer)

---

## Source Code Layer

### 1. Require signed commits for all contributors

Git commits are unsigned by default, which means any commit can be attributed to any identity. Enabling commit signing — using GPG, SSH keys, or Sigstore Gitsign — provides cryptographic assurance that a commit was made by the claimed author and was not tampered with in transit. Enforce commit signature verification in branch protection rules.

```bash
# Configure Git to sign all commits with SSH key
git config --global commit.gpgsign true
git config --global user.signingkey ~/.ssh/id_ed25519.pub
git config --global gpg.format ssh

# Verify signed commits in GitHub branch protection:
# Settings → Branches → Require signed commits
```

### 2. Enforce branch protection on all default and release branches

Branch protection rules prevent force pushes, deletion of protected branches, and merges without required status checks and reviews. At minimum, protected branches should require: at least one code review approval, all status checks to pass, and no force push. For high-criticality repositories, require two approvals and dismissal of stale reviews.

### 3. Require code review by a different person than the commit author

The developer who wrote the code should never be the sole approver of their own changes before they reach a protected branch. Enforce this in branch protection settings and audit regularly. This is a SLSA 4 requirement and an important defense against insider threats.

### 4. Enable and act on secret scanning

Secret scanning tools (GitHub Advanced Security, GitGuardian, Gitleaks) detect when credentials, API keys, private keys, or other secrets are committed to source repositories. Enable secret scanning on all repositories. Configure push protection to block commits containing known secret patterns before they are pushed. Treat a secret scanning alert as an incident: rotate the affected credential immediately, even if the commit is removed.

### 5. Integrate SAST into the pull request workflow

Static application security testing (SAST) identifies security vulnerabilities in source code before they are merged. Integrate SAST tools (Semgrep, CodeQL, Checkmarx) into the pull request CI workflow so that developers receive feedback at the point of code creation. Configure SAST findings of HIGH severity to block merge.

---

## Dependencies Layer

### 6. Pin all dependencies to exact versions

Version ranges in dependency manifests (`>=`, `^`, `~`) allow automatic uptake of new versions that may contain vulnerabilities, breaking changes, or malicious code. Pin every dependency to an exact version. Use automated tooling (Dependabot, Renovate) to propose version updates as pull requests that can be reviewed and tested before adoption.

### 7. Use lockfiles and commit them to source control

Lockfiles record the exact resolved dependency graph, including all transitive dependencies, with cryptographic hashes. Always use lockfiles (`package-lock.json`, `poetry.lock`, `Cargo.lock`, `go.sum`) and commit them. In CI, use commands that enforce lockfile integrity (`npm ci` not `npm install`, `pip install --require-hashes`). A modified lockfile should always be reviewed as a security-relevant change.

### 8. Verify dependency hashes in CI

Even with pinned versions, a package registry could theoretically serve a different artifact for the same version. Verify dependency hashes against expected values to detect tampering. Most modern package manager lockfiles include hashes — ensure your CI build is configured to verify them.

### 9. Route all dependency downloads through a private registry mirror

Direct internet access from build systems to public registries (npmjs.org, pypi.org, Maven Central) provides no opportunity to scan packages before use, creates dependency on external availability, and exposes you to dependency confusion attacks. Route all external package traffic through a private registry (Nexus, Artifactory, Harbor) that scans packages before caching them and controls the namespace.

### 10. Evaluate new dependencies before introduction

Every new open source dependency is a trust extension decision. Before adding a new dependency, evaluate: Is it actively maintained? Does it have a single maintainer (bus factor 1)? What is its OpenSSF Scorecard score? Does it have a history of unresponsive vulnerability handling? Is its license compatible with your software distribution model? Require this evaluation to be documented in the pull request that introduces the dependency.

### 11. Minimize transitive dependency footprint

Each transitive dependency is an indirect attack surface. Prefer libraries with minimal dependencies over feature-rich libraries with extensive dependency trees. Periodically audit dependency graphs using `npm ls`, `pip-tree`, `mvn dependency:tree` or equivalent and identify opportunities to replace heavyweight dependencies with simpler alternatives.

### 12. Subscribe to vulnerability notifications for critical dependencies

For the 20–50 most critical dependencies (by usage breadth and service criticality), subscribe to security advisories from the package maintainer and from databases like GHSA (GitHub Security Advisories) and OSV. Don't wait for automated scanning to alert you — proactive notification enables faster response.

### 13. Set and enforce SLAs for vulnerability remediation

Every organization needs a clear policy for how quickly critical and high vulnerabilities in dependencies must be addressed. A common standard is: Critical vulnerabilities within 7 days, High vulnerabilities within 30 days. Track compliance against these SLAs and escalate when they are missed. The SLA should account for the time to receive the alert, assess applicability, update the dependency, test, and deploy the fix.

---

## Build Layer

### 14. Use ephemeral, isolated build environments

Every CI build should run in a fresh environment — a new container, VM, or runner — that is provisioned for that build and destroyed afterward. Persistent build environments accumulate state that can be contaminated by previous builds. Ephemeral environments eliminate this risk and also improve reproducibility.

### 15. Never use production credentials in CI

CI builds should use dedicated service accounts with the minimum permissions required for their tasks. These accounts should not have access to production systems beyond artifact registry push access. Rotate CI credentials regularly. Use OIDC-based workload identity (GitHub Actions OIDC, Google Workload Identity Federation) where supported to eliminate long-lived static credentials entirely.

### 16. Treat build pipeline definitions as security-critical code

The build pipeline definition (GitHub Actions YAML, Jenkinsfile, .gitlab-ci.yml) determines what happens to your code in the CI environment. An attacker who can modify this file without review can exfiltrate source code, secrets, or inject malicious code into built artifacts. Apply the same review and approval requirements to build definitions as to application code. Prohibit execution of workflow changes from unreviewed pull requests.

### 17. Pin CI action versions by commit SHA, not by mutable tag

In GitHub Actions, referencing actions by mutable tag (e.g., `uses: actions/checkout@v4`) allows the action's owner or an attacker who compromises the repository to change what code runs in your pipeline. Reference actions by their commit SHA (e.g., `uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11`) to ensure you are always running the specific, reviewed version of the action.

```yaml
# Vulnerable: mutable tag reference
- uses: actions/checkout@v4

# Secure: immutable SHA reference
- uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11  # v4.1.1
```

### 18. Implement hermetic builds for critical services

For your highest-criticality services, implement hermetic builds where all inputs are declared and fetched before the build begins and network access is blocked during build execution. This provides the highest assurance that build output is determined solely by declared inputs. Bazel provides native hermetic build support; other build systems can be configured with network isolation using container network policies.

### 19. Generate and verify build provenance

Generate SLSA provenance for every production artifact and verify it before deployment. Provenance provides a cryptographically verifiable chain of custody linking the deployed artifact to the specific source commit and build run that produced it. Without provenance verification at deployment, you cannot distinguish between an artifact built from your authorized pipeline and one produced by a compromised or unauthorized build.

### 20. Scan artifact contents immediately after build

Run vulnerability and malware scanning on produced artifacts (container images, JARs, npm packages) immediately after the build completes, before the artifact is pushed to the registry. Catching vulnerabilities before publication is cheaper than managing deployed vulnerable artifacts. Use Trivy or Grype for container image scanning; integrate results into the CI status check.

---

## Artifacts Layer

### 21. Sign every production artifact before publication

Every artifact destined for production must be cryptographically signed. Signing binds the artifact to a specific signer identity and build event, enabling consumers to verify that the artifact they received is the same one that was produced by your authorized build system. Use Cosign with keyless signing (Sigstore) for container images — this eliminates key management complexity while providing strong provenance.

### 22. Generate SBOMs for every production artifact

An SBOM is the component inventory for your software. Without an SBOM, you cannot answer the question "which of our services uses Log4j 2.x?" when the next Log4Shell-class vulnerability is disclosed. Generate SBOMs at build time (not from source manifests alone) using Syft, cdxgen, or Trivy. Attach SBOMs to artifacts as signed attestations so that the SBOM-to-artifact relationship is verifiable.

### 23. Validate SBOM completeness and accuracy

An SBOM that is missing components provides false confidence. Validate SBOM completeness by comparing Syft's output against independent scanning (e.g., Trivy filesystem scan) and investigating discrepancies. Establish a minimum completeness threshold (e.g., 95% component coverage) and fail the build if this threshold is not met.

### 24. Store SBOMs in a centralized management platform

Individual SBOM documents stored per-artifact are difficult to search and correlate. Ingest all SBOMs into a centralized SBOM management platform (Dependency-Track, Grype in continuous mode) that provides: aggregate vulnerability dashboards, continuous re-scanning as new vulnerabilities are disclosed, license compliance reporting, and drill-down from vulnerability to affected service.

---

## Distribution Layer

### 25. Use immutable artifact tags

Mutable artifact tags (e.g., `:latest`, `:v1.2`) allow the content behind a tag to change without the tag changing. This creates the possibility of an attacker or insider replacing a vetted artifact with a malicious one. Configure your registry to prohibit tag mutation: in Harbor, enable immutable tags per project; in ECR, set imageTagMutability to IMMUTABLE. Always deploy using digest references (`image@sha256:...`), not mutable tags.

### 26. Implement registry vulnerability scanning with enforcement

Configure your registry to scan all images on push and on a recurring schedule. For high-criticality registries, configure the registry to block pull of images with critical unmitigated vulnerabilities. Balance security with operational continuity: implement an exception process for cases where an image must be pulled despite flagged vulnerabilities (with documented justification and time limit).

### 27. Restrict registry write access to CI service accounts only

Human write access to production artifact registries creates significant risk: accidental overwrites, unauthorized modifications, and the challenge of tracing who pushed what when. Limit artifact publishing to CI service accounts operating through the authorized build pipeline. All human access to the registry should be read-only (for debugging) and fully logged.

### 28. Record all distribution events in an audit trail

Every artifact push, pull, tag operation, and signature event should be logged in a tamper-evident audit trail. This provides forensic capability when investigating supply chain incidents — you can determine exactly which artifact versions were in use at which times and by which systems.

---

## Deployment Layer

### 29. Verify artifact signatures at the admission controller, not just at build time

Artifact signatures verified only during CI provide no protection against an attacker who bypasses CI and pushes directly to the registry. Signature verification must occur at the point of deployment — in the Kubernetes admission controller — so that only correctly signed artifacts from authorized build pipelines can run in production. Kyverno and OPA Gatekeeper both support cosign signature verification policies.

### 30. Enforce provenance-based admission for critical services

For your highest-criticality services, require not just artifact signatures but verified provenance: evidence that the artifact was built from an authorized source repository, by an authorized build pipeline, and that the provenance attestation itself is non-falsifiable (SLSA Level 3+). This provides the strongest protection against unauthorized code execution in production.

### 31. Implement and test supply chain incident response procedures

Supply chain incidents are distinct from typical security incidents — they may require rolling back deployed software across many services simultaneously and coordinating with external vendors. Document specific supply chain incident scenarios (compromised dependency, compromised build system, registry compromise) with defined response procedures, communication plans, and rollback procedures. Test these procedures at least annually through tabletop exercises.

### 32. Monitor deployed workloads against the SBOM inventory

Continuously compare the SBOMs of deployed workloads against the current vulnerability database. When a new CVE is disclosed that affects a component in a deployed artifact's SBOM, an alert should fire automatically — without requiring a new scan of the artifact. This provides near-real-time vulnerability awareness for deployed software.

### 33. Implement runtime integrity monitoring for critical workloads

For the most critical workloads, implement runtime integrity monitoring using tools like Falco, Tetragon, or eBPF-based security platforms. These tools can detect anomalous behavior indicative of a supply chain compromise — unexpected file writes, network connections to unexpected destinations, privilege escalation attempts — in real time, enabling rapid response.
