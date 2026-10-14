Here is an end-to-end scenario demonstrating how [`grc_bundle.py`](file:///Users/byronturner-pro/Desktop/GRC%20Bundle%20Review%20Pipeline/grc_bundle.py) is used during an audit review of a release bundle, along with exact terminal command invocations and their output.

---

### Scenario Background

* **Artifact Under Review**: `auth-service-v1.2.0.bundle` (a Git release bundle provided by the engineering team).
* **Expected Release Tag**: `v1.2.0`
* **Recorded Baseline SHA-256**: `e5b7a1c93f48d02e6b7c5a91f83d2e04a7b1c3d5e7f9a2b4c6d8e0f2a4b6c8d0`
* **Objective**: Ingest, verify integrity, restore into an isolated read-only workspace, generate audit provenance, run security checks, and tear down the workspace.

---

### Step 1: Pre-Extraction Integrity Check (`verify`)

In **Phase 1 (Pull & Verify)**, the compliance analyst checks the cryptographic digest and validates that the Git object history inside the bundle is sound prior to extraction:

```bash
python3 grc_bundle.py verify auth-service-v1.2.0.bundle \
  --expected-sha256 e5b7a1c93f48d02e6b7c5a91f83d2e04a7b1c3d5e7f9a2b4c6d8e0f2a4b6c8d0
```

**Terminal Output:**
```text
[*] Starting Pull & Verify for bundle: auth-service-v1.2.0.bundle
    -> SHA-256 Digest: e5b7a1c93f48d02e6b7c5a91f83d2e04a7b1c3d5e7f9a2b4c6d8e0f2a4b6c8d0
    -> Cryptographic checksum verified against session baseline: MATCH
    -> Git bundle object verification: VALID
[SUCCESS] Bundle verification passed for: auth-service-v1.2.0.bundle
```

---

### Step 2: Restoring into an Ephemeral Workspace (`restore`)

In **Phase 2 (Restore)**, the analyst unpacks the bundle into an ephemeral workspace, checks out tag `v1.2.0`, and applies read-only permissions to prevent any analysis scanner from mutating source files:

```bash
# Using the wrapper or direct python script:
./grc bundle restore auth-service-v1.2.0.bundle \
  --workspace ./ephemeral_workspace \
  --ref v1.2.0 \
  --expected-sha256 e5b7a1c93f48d02e6b7c5a91f83d2e04a7b1c3d5e7f9a2b4c6d8e0f2a4b6c8d0 \
  --read-only
```

**Terminal Output:**
```text
[*] Starting Pull & Verify for bundle: auth-service-v1.2.0.bundle
    -> SHA-256 Digest: e5b7a1c93f48d02e6b7c5a91f83d2e04a7b1c3d5e7f9a2b4c6d8e0f2a4b6c8d0
    -> Cryptographic checksum verified against session baseline: MATCH
    -> Git bundle object verification: VALID
[*] Extracting bundle into ephemeral workspace: /Users/byronturner-pro/Desktop/GRC Bundle Review Pipeline/ephemeral_workspace
    -> Cloned bundle repository successfully.
    -> Checked out reference: v1.2.0
    -> Checked out Commit: 4a9f2bc1 (HEAD -> v1.2.0, tag: v1.2.0)
    -> Author: Release Automation <sec-ops@company.internal>
    -> Subject: Release v1.2.0: Core authentication microservice
[*] Provenance manifest generated: bundle_provenance.json
    -> Applied read-only filesystem permissions across source tree.
[SUCCESS] Bundle successfully restored and ready for Phase 3 (Analyze).
```

---

### Step 3: Inspecting the Generated Audit Manifest

The tool places [`bundle_provenance.json`](file:///Users/byronturner-pro/Desktop/GRC%20Bundle%20Review%20Pipeline/DevSecOps%20Engineering%20&%20Compliance%20Workspace%20Layout.md#L68) at the root of the workspace. This manifest serves as the formal **Bundle Identifier** required for FedRAMP / DoD SCR packages:

```bash
cat ./ephemeral_workspace/bundle_provenance.json
```

**Terminal Output:**
```json
{
  "manifest_schema": "grc-bundle-provenance-v1",
  "session_id": "7f8b91a2-c34d-4e5f-89ab-0123456789cd",
  "bundle_identifier": "e5b7a1c93f48d02e6b7c5a91f83d2e04a7b1c3d5e7f9a2b4c6d8e0f2a4b6c8d0",
  "bundle_source_path": "/Users/byronturner-pro/Desktop/GRC Bundle Review Pipeline/auth-service-v1.2.0.bundle",
  "bundle_size_bytes": 14829312,
  "bundle_sha256": "e5b7a1c93f48d02e6b7c5a91f83d2e04a7b1c3d5e7f9a2b4c6d8e0f2a4b6c8d0",
  "workspace_path": "/Users/byronturner-pro/Desktop/GRC Bundle Review Pipeline/ephemeral_workspace",
  "checked_out_ref": "v1.2.0",
  "commit_metadata": {
    "commit_hash": "4a9f2bc18d3e710294abcf581029384756201948",
    "short_hash": "4a9f2bc1",
    "author_name": "Release Automation",
    "author_email": "sec-ops@company.internal",
    "author_date": "Wed Oct 14 07:15:22 2026 -0400",
    "subject": "Release v1.2.0: Core authentication microservice",
    "ref": "HEAD -> v1.2.0, tag: v1.2.0"
  },
  "restored_at": "2026-10-14T12:50:11.492104+00:00",
  "status": "RESTORED",
  "ephemeral": true,
  "verification": {
    "session_id": "7f8b91a2-c34d-4e5f-89ab-0123456789cd",
    "bundle_sha256": "e5b7a1c93f48d02e6b7c5a91f83d2e04a7b1c3d5e7f9a2b4c6d8e0f2a4b6c8d0",
    "checksum_verified": true,
    "git_bundle_valid": true,
    "contained_references": [
      {
        "commit": "4a9f2bc18d3e710294abcf581029384756201948",
        "ref": "refs/tags/v1.2.0"
      }
    ]
  }
}
```

---

### Step 4: Running Phase 3 (Analyze) Against the Restored Workspace

Once restored, the analyst executes the custom Semgrep ruleset and the DISA STIG SBOM analyzer against the extracted code:

```bash
# 1. Execute Custom Baseline Semgrep Ruleset
semgrep scan \
  --config="./custom-baseline-ruleset.yaml" \
  --json \
  --output="./ephemeral_workspace/semgrep_findings.json" \
  ./ephemeral_workspace

# 2. Execute DISA STIG SBOM Applicability Matrix Engine
python3 sbom_analyzer.py \
  --sbom "./ephemeral_workspace/bom.json" \
  --format markdown \
  --output="./ephemeral_workspace/stig_applicability_matrix.md"
```

---

### Step 5: Post-Audit Ephemeral Teardown (`clean`)

To uphold the core design rule in [`Design Rules and AOCs.md`](file:///Users/byronturner-pro/Desktop/GRC%20Bundle%20Review%20Pipeline/Design%20Rules%20and%20AOCs.md#L6) (*"The workspace is ephemeral and is only used for GRC analysis. Once the analysis is complete, the workspace is destroyed and the bundle is deleted"*), the analyst purges the workspace and original bundle:

```bash
python3 grc_bundle.py clean \
  --workspace ./ephemeral_workspace \
  --delete-bundle auth-service-v1.2.0.bundle
```

**Terminal Output:**
```text
[*] Destroying ephemeral workspace: /Users/byronturner-pro/Desktop/GRC Bundle Review Pipeline/ephemeral_workspace
    -> Workspace directory deleted.
[*] Deleting processed bundle: /Users/byronturner-pro/Desktop/GRC Bundle Review Pipeline/auth-service-v1.2.0.bundle
    -> Bundle file deleted.
[SUCCESS] Ephemeral cleanup complete.
```

---

### Error Handling Example: Tampered Bundle

If an untrusted or altered bundle with a mismatched checksum is supplied, execution immediately aborts before extraction occurs:

```bash
python3 grc_bundle.py restore tampered.bundle \
  --expected-sha256 e5b7a1c93f48d02e6b7c5a91f83d2e04a7b1c3d5e7f9a2b4c6d8e0f2a4b6c8d0
```

**Terminal Output (Aborted):**
```text
[*] Starting Pull & Verify for bundle: tampered.bundle
    -> SHA-256 Digest: 111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000
[ERROR] SHA-256 mismatch!
        Expected: e5b7a1c93f48d02e6b7c5a91f83d2e04a7b1c3d5e7f9a2b4c6d8e0f2a4b6c8d0
        Computed: 111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000
[FATAL] Operation failed: Bundle cryptographic integrity verification failed.
```