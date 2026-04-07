# Supply Chain Incident Response Playbook

This playbook defines structured response procedures for software supply chain security incidents. It covers detection, containment, eradication, and recovery for the most common attack categories affecting modern software delivery pipelines: compromised dependencies, build system intrusions, artifact tampering, and identity/credential compromise in CI/CD systems.

Use this playbook in conjunction with the [Software Supply Chain Security Framework](framework.md), [SBOM Guide](sbom-guide.md), and your organization's broader incident response policy.

---

## Scope and Applicability

This playbook applies to incidents that affect the integrity, authenticity, or confidentiality of software artifacts produced or consumed by your organization. It does not replace general security incident response procedures — it supplements them with supply chain-specific triage, evidence collection, and remediation steps.

**In scope:**
- Compromised open source dependencies (malicious package, typosquatting, dependency confusion)
- Build system compromise (CI/CD runner, build server, artifact registry)
- Artifact tampering or signature invalidation
- Leaked or stolen pipeline credentials (OIDC tokens, signing keys, registry secrets)
- Compromised third-party tooling integrated into the pipeline (plugins, actions, orbs)

**Out of scope:**
- Runtime application security incidents (covered by your IR policy)
- Infrastructure-level intrusions unrelated to software delivery

---

## Severity Classification

| Severity | Criteria | Response SLA |
|----------|----------|--------------|
| **P1 — Critical** | Confirmed malicious code in a released artifact; active build system compromise; signing key exfiltration | Immediate — all hands |
| **P2 — High** | Suspicious artifact behavior with unconfirmed origin; CI/CD credential leak with unknown blast radius; dependency with known malicious version published | < 2 hours |
| **P3 — Medium** | Dependency with newly disclosed CVE (CVSS ≥ 7.0) in production artifact; expired or untrusted signing certificate; single environment credential exposure | < 24 hours |
| **P4 — Low** | Policy violation without confirmed compromise; deprecated dependency; SBOM gap identified in audit | Next sprint |

---

## Playbook 1: Compromised Open Source Dependency

**Trigger:** Security scanner, package registry advisory, or threat intelligence feed reports a malicious or trojanized version of a dependency used in your build.

### Phase 1 — Detection and Triage (0–30 minutes)

1. Identify the affected package name, version range, and CVE or advisory reference.
2. Query your SBOM inventory to determine which artifacts and services consume the affected package:
   ```bash
   # Example: query Dependency-Track for affected component
   curl -H "X-Api-Key: $DT_API_KEY" \
     "https://dependency-track.internal/api/v1/component/search?name=<package>&version=<version>"
   ```
3. Determine whether the affected version is present in any artifact currently deployed to production, staging, or accessible environments.
4. Classify severity using the table above. If P1 or P2, page the on-call security engineer and engage the incident commander.
5. Preserve evidence: capture current SBOM snapshots for all affected services before any remediation begins.

### Phase 2 — Containment (30–90 minutes)

1. **Block ingestion** of the affected package version at the artifact proxy (Nexus, Artifactory, or equivalent):
   - Add the package version to the blocklist in your artifact repository proxy configuration.
   - Verify the block by attempting a resolve from a fresh build environment.

2. **Halt affected pipelines** if the malicious version is being actively fetched:
   - Disable or pause CI/CD jobs that produce artifacts using the affected dependency.
   - Set a pipeline gate in your Policy-as-Code engine (OPA/Kyverno) to reject builds containing the component.

3. **Assess deployed artifacts**: for each production service confirmed to use the affected version:
   - Determine whether the malicious behavior requires immediate service shutdown or can be mitigated by WAF/network controls.
   - Do not make this determination without input from the application security team and service owner.

4. Notify stakeholders: affected service owners, platform security, CISO function, legal/compliance if data exfiltration is suspected.

### Phase 3 — Eradication (1–4 hours)

1. Update the dependency to a clean version, or pin to the last known-good version if a clean release is not yet available.
2. Rebuild all affected artifacts from source using ephemeral, isolated build environments. Do not reuse previously cached layers.
3. Re-sign all rebuilt artifacts using your standard signing key (Cosign/Sigstore). Generate updated SBOMs for each rebuilt artifact.
4. Validate the new build against your SBOM policy: confirm the malicious version is absent from the dependency graph at all levels (direct and transitive).
5. Scan rebuilt artifacts with at least two independent vulnerability scanners (e.g., Grype + Trivy) before promotion.

### Phase 4 — Recovery and Deployment (4–8 hours)

1. Deploy rebuilt artifacts through the full promotion pipeline — do not bypass staging validation gates.
2. Monitor deployment for anomalous behavior for a minimum of 30 minutes before declaring the incident resolved.
3. Update your artifact blocklist to permanently exclude the malicious version.
4. Re-enable paused pipelines only after the remediated dependency version is confirmed available and proxied.

### Phase 5 — Post-Incident Review

1. Document: affected artifact inventory, timeline, blast radius, remediation steps taken.
2. Identify detection gap: how was the malicious package not caught before it reached production?
3. Assess SBOM completeness: was the affected component present in all relevant SBOMs?
4. Update SBOM policy if the incident revealed a gap in transitive dependency tracking.
5. File findings in your compliance evidence repository if regulatory notification may be required.

---

## Playbook 2: Build System Compromise

**Trigger:** Evidence of unauthorized access to a CI/CD runner, build server, or pipeline orchestrator — including anomalous outbound network connections, unexpected process execution, or exfiltration of build secrets.

### Phase 1 — Detection and Triage (0–30 minutes)

1. Isolate the affected runner or build node immediately. In cloud environments, detach from the network; do not terminate — preserve for forensics.
2. Identify the time window of compromise: review runner logs, job execution history, and audit logs from the CI/CD platform.
3. Enumerate all artifacts produced by the compromised runner during the suspected window. Tag them as potentially tainted.
4. Determine whether signing keys, registry credentials, or OIDC tokens were accessible to the compromised runner.
5. Classify as P1 if any of the following are true:
   - Artifacts produced during the window have been released to customers
   - Signing keys were accessible on the compromised runner
   - The runner had write access to a production artifact registry

### Phase 2 — Containment (30–60 minutes)

1. **Revoke all credentials** accessible by the compromised runner:
   - Rotate any long-lived secrets stored in CI/CD secret stores.
   - Revoke and reissue OIDC subject bindings if the platform allows it.
   - Rotate registry pull/push credentials.
   - If a code signing key was accessible: treat the key as compromised (see Playbook 4 for key revocation).

2. **Quarantine tainted artifacts**: mark all artifacts produced during the compromise window as untrusted in your artifact registry. Do not delete — retain for forensic analysis.

3. **Block promotion** of tainted artifacts: update pipeline gates to reject artifacts with build provenance from the quarantined runner or time window.

4. **Provision clean runners**: deploy a new set of ephemeral runners from a known-good base image. Verify the base image digest against your golden image registry.

### Phase 3 — Forensic Investigation (parallel with containment)

1. Capture a full snapshot of the compromised runner's disk and memory if feasible.
2. Review CI/CD audit logs for:
   - Who triggered the affected jobs
   - What environment variables were exposed
   - What external network connections were made during job execution
   - Whether any step injected unexpected commands (script injection via PR title, issue body, etc.)
3. Review artifact registry access logs: was the compromised runner used to publish, modify, or delete artifacts beyond its expected scope?
4. Preserve all evidence with chain-of-custody documentation before any remediation that might destroy forensic artifacts.

### Phase 4 — Eradication

1. Identify the root cause of compromise: misconfigured runner permissions, script injection, compromised base image, or credential exposure.
2. Remediate root cause before restoring any affected pipeline.
3. Rebuild all artifacts produced during the compromise window from clean source, on verified clean runners.
4. Re-sign rebuilt artifacts and generate new provenance attestations. The previous attestations are invalid.

### Phase 5 — Recovery

1. Restore pipeline operation using new runners and rotated credentials.
2. If signing keys were compromised: complete the signing key rotation and notify any downstream consumers relying on the old key for verification.
3. Conduct a full pipeline security audit using the [Pipeline Security Hardening Checklist](../../secure-pipeline-templates/docs/hardening-checklist.md) before resuming normal operations.

---

## Playbook 3: Artifact Tampering or Signature Failure

**Trigger:** An artifact fails signature verification at deployment time, a checksum mismatch is detected, or an artifact registry audit reveals unexpected mutations to a previously published artifact.

### Phase 1 — Detection and Triage

1. Record the exact artifact reference (name, version/tag, digest) and where the failure was detected (deployment gate, registry scanner, consumer verification).
2. Retrieve the artifact's current digest and compare against the digest recorded in the build provenance attestation or SBOM.
3. Determine the scope: is the tampered artifact in a shared registry used by multiple teams or customers?
4. Retrieve and inspect the signing certificate chain. Verify whether the signature was created with an expected key and within the certificate's validity window.

### Phase 2 — Containment

1. Immediately quarantine the artifact: set the registry tag to point to a known-good previous version and flag the tampered artifact with a status annotation (do not delete).
2. Notify all known consumers of the affected artifact reference. If the artifact is a base image or library used downstream, treat scope as potentially broad.
3. Block deployment of the artifact across all environments via pipeline policy.

### Phase 3 — Investigation

1. Review registry access logs for the time window between the last known-good signature and the time of detected mismatch.
2. Determine whether the mutation occurred:
   - At the registry (unauthorized write/overwrite)
   - In transit (unlikely if TLS is enforced; include in investigation regardless)
   - At build time (artifact produced without signing or with wrong key)
3. If registry-side tampering is confirmed: treat as a build system compromise (Playbook 2) and engage the registry platform team.

### Phase 4 — Eradication and Recovery

1. Rebuild the artifact from verified source at the tagged commit.
2. Re-sign with a valid certificate and generate a new provenance attestation.
3. Publish the rebuilt artifact, preserving the original version tag but updating the digest reference.
4. Circulate updated digest to downstream consumers.

---

## Playbook 4: Pipeline Credential Compromise

**Trigger:** Evidence of unauthorized use of a CI/CD credential — including OIDC tokens used outside their expected subject/audience, registry credentials used from unexpected IP ranges, or API keys appearing in public repositories.

### Phase 1 — Immediate Response (0–15 minutes)

1. Revoke the compromised credential immediately — do not wait for investigation to complete.
2. Identify the credential type:
   - **Long-lived secret (API key, password, token):** revoke via the issuing platform immediately.
   - **OIDC short-lived token:** tokens expire naturally; revoke the OIDC subject binding and rotate the target role/identity.
   - **Signing key:** revoke the certificate and initiate key rotation (this requires coordination with PKI or Sigstore trust root).
3. Determine the blast radius: what systems could the credential access? Review access logs for the preceding 30 days.

### Phase 2 — Containment and Investigation

1. Audit all actions taken with the compromised credential during the suspected exposure window.
2. Identify any artifacts produced, published, or modified using the compromised credential. Treat all such artifacts as potentially tainted.
3. If a signing key was compromised:
   - Rotate the key and publish the new public key to your transparency log.
   - Issue a notice to downstream consumers who rely on signature verification with the old key.
   - Rebuild and re-sign all artifacts previously signed with the compromised key if they are still in active use.

### Phase 3 — Eradication

1. Remove the secret from any location where it appeared in plaintext (repository, logs, issue tracker, Slack). Use GitHub's secret scanning or GitLab's push protection retroactive scan to confirm removal.
2. Rotate all credentials that could have been accessed by the same compromised credential (lateral movement scope).
3. Implement or strengthen the preventive control that would have blocked this exposure (pre-commit hooks, secret scanning CI gate, OIDC migration, external secret management).

---

## Evidence Collection Requirements

For all supply chain incidents, collect and preserve the following before remediation:

| Evidence Type | Source | Retention |
|---------------|--------|-----------|
| SBOM snapshots for affected artifacts | Dependency-Track / SBOM store | 2 years |
| CI/CD job logs for the affected window | Pipeline platform audit logs | 1 year |
| Artifact registry access logs | Registry audit logs | 1 year |
| Build provenance attestations | Rekor transparency log / internal store | Indefinitely |
| Signing certificate chain | PKI / Sigstore | Certificate lifetime + 2 years |
| Forensic disk/memory images | Compromised runner | 90 days post-resolution |
| Incident timeline document | Internal IR tracking system | 3 years |

---

## Regulatory Notification Thresholds

Consult your legal and compliance team immediately if any of the following conditions apply:

- Personal data was potentially exposed through a compromised artifact or credential
- A customer-facing software release is confirmed or suspected to contain malicious code
- The incident falls under EU NIS2 Article 23 significant incident thresholds (critical infrastructure operators)
- The incident involves a software product subject to EU Cyber Resilience Act requirements
- US federal contractors must evaluate Executive Order 14028 notification obligations

---

## Post-Incident Reporting Template

Use this template for formal post-incident documentation:

```
Incident ID: [IR-YYYY-NNN]
Date detected:
Date resolved:
Severity:
Incident commander:
Playbook(s) invoked:

Summary:
[2–3 sentence description of what happened]

Timeline:
[Table: timestamp | action | actor]

Affected artifacts:
[List with name, version, registry, and deployment environments]

Root cause:
[Technical root cause — specific, not generic]

Detection gap:
[Why was this not caught by automated controls?]

Remediation steps taken:
[Numbered list of what was done]

Control improvements:
[What specific control gaps will be closed, by whom, by when]

Regulatory notification required:
[Yes/No — if Yes, which frameworks, and what was communicated]

Lessons learned:
[Non-obvious findings only]
```

---

## Playbook 5: AI/ML Model Supply Chain Incident

**Trigger:** Evidence of a compromised, poisoned, or substituted AI/ML model in the software supply chain — including unexpected model behavior, mismatched model hash verification, unauthorized model registry access, or a public disclosure of a backdoored model used by the organization.

This playbook covers threats specific to AI/ML model supply chains: model weight poisoning, training data contamination, malicious fine-tuning, model hub hijacking, and inference-time model substitution. These threats share structural similarity with traditional software supply chain attacks but require distinct response procedures due to the opaque nature of model weights and the difficulty of behavioral analysis.

### Threat Categories Covered

| Threat | Description |
|--------|-------------|
| **Model weight poisoning** | Pre-trained model contains backdoored behavior triggered by specific input patterns |
| **Training data poisoning** | Model fine-tuned on malicious data that subtly skews output toward adversarial outcomes |
| **Model hub hijacking** | Attacker gains write access to the organization's model hub namespace and replaces a model |
| **Malicious fine-tune distribution** | Community-shared fine-tune contains hidden behavior not present in the base model |
| **Inference-time substitution** | Attacker substitutes a different model weight file for the expected one at serving time |

### Phase 1 — Detection and Triage (0–1 hour)

1. **Identify the scope:** Determine which models, versions, and production services are potentially affected. Query your model registry and model SBOM inventory:
   ```bash
   # Query model registry for affected model versions
   # Replace with your registry's query interface
   mlflow models list --name <model-name> --filter "tags.source = 'external'"
   ```

2. **Verify model hashes against recorded manifests:** Compare the hash of the model weights file in production against the hash recorded in your Model Bill of Materials (ML-SBOM) or model card:
   ```python
   import hashlib

   def check_model_integrity(model_path: str, expected_hash: str) -> bool:
       sha256 = hashlib.sha256()
       with open(model_path, "rb") as f:
           for chunk in iter(lambda: f.read(65536), b""):
               sha256.update(chunk)
       actual = f"sha256:{sha256.hexdigest()}"
       if actual != expected_hash:
           print(f"INTEGRITY FAILURE: {model_path}")
           print(f"  Expected: {expected_hash}")
           print(f"  Actual:   {actual}")
           return False
       return True
   ```

3. **Classify severity:**
   - **P1 — Critical:** Model confirmed compromised and actively serving production traffic; model outputs data to customers
   - **P2 — High:** Model hash mismatch confirmed; model in staging; or model's role is internal/non-customer-facing
   - **P3 — Medium:** Suspicious model source (untrusted origin, no provenance attestation) but no confirmed compromise

4. Notify platform security, the application team, and the CISO function. For P1, engage legal if customer data may have been influenced by manipulated model outputs.

### Phase 2 — Containment (1–2 hours)

1. **Halt inference serving** from the affected model version:
   - Set the model registry stage to `Archived` or `Deprecated` to prevent new deployments.
   - Roll back the serving endpoint to the previous model version if a known-good version is available.
   - If no known-good version exists, consider taking the inference service offline until a clean model can be sourced.

2. **Block model download in CI/CD:** Add the affected model identifier to the pipeline's blocked dependency list. Prevent any new build from fetching this model version.

3. **Isolate the affected service** if the model is serving production traffic and P1 criteria apply:
   - Apply network policy to limit the service's outbound connections (prevent potential data exfiltration via inference manipulation).
   - Enable enhanced logging on the service to capture all inference requests for forensic review.

4. **Preserve the compromised model file** for forensic analysis before any cleanup. Do not delete — retain in a quarantined storage location with access restricted to the incident response team.

### Phase 3 — Forensic Analysis (parallel with containment)

1. **Behavioral analysis:** If resources permit, run the suspect model in an isolated environment with a battery of adversarial inputs designed to trigger known backdoor patterns (BadNets trigger patterns, trojaned classifier inputs, instruction-following override attempts for LLMs).

2. **Provenance investigation:** Trace the model's origin:
   - What is the model hub source (Hugging Face, Ollama, internal)?
   - When was it downloaded? By whom?
   - Was the download hash-verified against a recorded expected hash?
   - Has the model hub namespace been accessed by unauthorized parties?

3. **Training data audit (if fine-tuned internally):**
   - Review the training dataset for known poisoning patterns (label flips, adversarial examples, instruction override text in fine-tuning data).
   - If the fine-tuning dataset was sourced from external contributions, treat all contributed samples as potentially poisoned.

4. **Inference log review:** Analyze production inference logs for anomalous patterns: unexpected output distributions, systematic classification errors in specific input categories, outputs with embedded exfiltration patterns (URLs, encoded data in responses).

### Phase 4 — Eradication

1. **Source a clean model:**
   - For publicly available base models: re-download from the official source and verify against the model card's published hash.
   - For internally fine-tuned models: rebuild from a clean base model and a verified training dataset. Do not reuse any data that was not fully provenance-traced.
   - For internally trained models: retrain from verified data if dataset compromise is suspected.

2. **Verify the replacement model's integrity and provenance:**
   - Confirm hash matches model card or release notes
   - Confirm model source repository commit SHA matches expected training run record
   - Generate a new Model SBOM (ML-SBOM) per [ML-2 controls](framework.md#ml-2-model-sbom-model-bill-of-materials)

3. **Store in private model registry:** Register the clean model in your organization's private model registry (not fetched from a public hub at inference time). Apply access controls per [ML-3](framework.md#ml-3-private-model-registry).

4. **Sign the model artifact:** Package the model weights as an OCI artifact and sign with Cosign for deployment-time verification where applicable.

### Phase 5 — Recovery and Validation

1. Deploy the clean model through the full staging validation pipeline — do not bypass evaluation gates.
2. Run a post-deployment behavioral validation suite confirming the restored model behaves within expected output distributions.
3. Monitor production inference for at least 24 hours post-restoration for anomalous output patterns.
4. Notify downstream consumers (API clients, internal teams) of the incident and restoration timeline.

### Phase 6 — Post-Incident Review

1. Document: affected model versions, inference traffic volume during compromise window, nature of any anomalous outputs observed.
2. Assess whether any customer-visible outputs were materially affected by the compromised model. Engage legal if regulatory notification may be required.
3. Implement missing controls from the [AI/ML Supply Chain Security section](framework.md#aiml-model-supply-chain-security) of the framework:
   - Was ML-1 (model provenance verification) in place? If not, add to roadmap as Critical.
   - Was ML-2 (model SBOM) in place? If not, add to roadmap as High.
   - Was ML-3 (private model registry) in place? If not, add to roadmap as High.
4. Update the SBOM and model provenance records to reflect all models currently serving production traffic.

---

## Integration with Framework Documentation

- **Prevention controls:** [Software Supply Chain Security Framework](framework.md) — Section 3: Control Implementation
- **SBOM management:** [SBOM Format and Tool Selection Guide](sbom-guide.md)
- **Pipeline hardening:** [Pipeline Security Hardening Checklist](../../secure-pipeline-templates/docs/hardening-checklist.md)
- **Threat modeling:** [Secure CI/CD Threat Model](../../secure-ci-cd-reference-architecture/docs/threat-model.md)
- **Compliance reporting:** [Compliance Automation Framework](../../compliance-automation-framework/docs/framework.md)
- **Maturity baseline:** [DevSecOps Maturity Assessment Scorecard](../../devsecops-maturity-model/docs/assessment-scorecard.md) — Domain 6: Supply Chain Security

---

*Part of the Techstream Software Supply Chain Security Framework. Licensed under Apache 2.0.*
