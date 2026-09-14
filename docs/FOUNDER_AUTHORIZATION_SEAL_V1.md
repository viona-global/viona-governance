# VIONA Founder Authorization Seal V1

## Status and boundary

This document specifies the Pack B3 candidate implementation. The workflow is not active on protected `main`, has not been dispatched, and has issued no live seal. Its merge, later activation, and every use of a seal require separate authority.

The Founder Authorization Seal certifies immutable or frozen authority facts for exactly one pull request. It does not decide whether the pull request currently has an eligible approval, resolved conversations, successful checks, valid protection, queue eligibility, or mergeability. GitHub native protection and the future `merge_group` gate must establish those mutable facts at merge time.

The global VIONA freeze and the GitHub-governance migration freeze remain active. A seal is evidence of a bounded freeze exception; it is not a freeze release, required-check success, review, queue admission, or merge command.

## Trusted issuer

V1 fixes the issuer contract to:

- repository: `viona-global/viona-governance`
- repository ID: `1370004364`
- protected branch: `main`
- workflow: `.github/workflows/founder-authorization-seal.yml`
- event: `workflow_dispatch`
- Founder actor and triggering actor: `laoton80-del`
- run attempt: `1`
- target allowlist: `laoton80-del/Ket-noi-eu`
- target repository ID: `1213874552`
- target repository node ID: `R_kgDOSFpBeA`

The script requires `GITHUB_REF_PROTECTED=true`, the exact workflow reference, an exact workflow commit SHA equal to the run SHA, and consistent actor identities. Workflow input cannot supply or override the Founder identity, issuer identity, target head SHA, scope digests, path set, payload digest, repository ID, review identity, or workflow provenance.

The workflow accepts only these subject inputs:

- exact allowlisted target repository
- positive pull-request number
- one explicit freeze-scope constant
- exact lowercase merge mode `squash`
- exact provenance constant `FOUNDER_MANUAL_WORKFLOW_DISPATCH_V1`

The target is public and the implementation uses unauthenticated, allowlisted HTTPS `GET` requests. The governance repository token is not sent to the target repository. HTTP errors, rate limits, non-JSON responses, incomplete responses, and malformed fields fail closed.

## Workflow authority and permissions

`workflow_dispatch` is the only trigger. There is no `push`, `pull_request`, `pull_request_target`, `workflow_call`, `workflow_run`, `repository_dispatch`, comment, or schedule trigger.

Permissions are limited to:

- `contents: read`
- `pull-requests: read`
- `id-token: write`
- `attestations: write`

The last two permissions allow GitHub artifact attestation in this public repository. GitHub documents artifact attestations as available for public repositories on GitHub Free, Pro, and Team. V1 grants no `contents`, pull-request, checks, statuses, actions, deployments, packages, or administration write permission.

The workflow creates artifacts only in its own governance workflow run. It cannot edit the target PR, submit a review, create a target check or status, dispatch a target workflow, change a branch, alter permissions or protection, merge, or deploy.

## Live derivation and complete inventory

The caller identifies a subject. The workflow derives the security facts from GitHub's live target API and requires the numeric and node identities to match the Pack B0 pre-transfer seal:

- repository numeric ID, node ID, full name, visibility, default branch, and active state
- PR number, open/draft/merged state, exact head SHA and branch, base, and changed-file count
- complete changed-file inventory
- changed-path-set digest
- reviewed-scope digest
- exact file payload identities where the selected policy requires them

PRs must be open, non-draft, unmerged, based on `master`, and use a head in the same allowlisted repository. Fork heads are rejected in V1.

Changed files are read in pages of 100 with a 50-page safety ceiling. Each next-page link must remain on either the exact slug endpoint or GitHub's equivalent endpoint containing the pinned numeric repository ID, contain only the expected sequential page and fixed page-size parameters, and never repeat. A malformed link, unexpected host, duplicate path, unsupported status, API error, terminal count mismatch, or safety-ceiling hit while more pages exist fails closed.

## Canonical scope algorithms

All text is UTF-8. Records use their exact GitHub lowercase status and repository-relative POSIX path. Sorting compares UTF-8 bytes without locale or case folding. There is no terminal newline in digest preimages.

The changed-path-set digest is SHA-256 lowercase hex over:

```text
filename
```

for every unique changed file, sorted by filename and joined with LF.

The reviewed-scope digest preserves the current VIONA representation:

```text
status<TAB>filename<TAB>previous_filename-or-empty
```

Records are sorted by filename, joined with LF, and hashed with SHA-256 lowercase hex. Caller-supplied digests are not inputs.

When a policy requires payload binding, each exact file is fetched from the Contents API at the exact live PR head. Base64 is decoded without text or line-ending normalization. The decoded bytes must match both the Git blob SHA reported by the PR file record and the content response. Each file's raw SHA-256 is then bound into:

```text
path<TAB>sha256
```

sorted by path, joined with LF, and SHA-256 hashed.

## Freeze-scope policies

V1 recognizes exactly two tokens.

### Merge-guardrail remediation

`FREEZE_EXCEPTION_FOR_MERGE_GUARDRAIL_REMEDIATION_ONLY` requires a `fix/viona-` or `codex/viona-` branch and restricts every changed path to the explicit V1 allowlist in the script. That allowlist contains only the existing merge-authorization workflow, merge-gate and guarded-merge scripts and tests, and their three current PR459 design/evidence documents. Product source, runtime source, database migrations, deployments, package manifests, and any unlisted path fail closed. Renames fail closed. The seal records `payload_digest: null`; exact head and scope digests still bind the immutable candidate.

### PR459 Operating Protocol V2 promotion

`FREEZE_EXCEPTION_FOR_PR459_OPERATING_PROTOCOL_V2_CANONICAL_PROMOTION_ONLY` hard-codes:

- repository `laoton80-del/Ket-noi-eu`
- PR number `459`
- branch `docs/viona-operating-protocol-v2-canonical-promotion`
- base `master`
- merge mode `squash`
- exact seven path/status records
- exact seven raw file SHA-256 values
- reviewed-scope digest `5d242aeae7ad51dbf782dd7a38a2d94f314d1ce5410106dfb9c03aebc9802713`
- payload digest `6a7e59d1b2948f16999bff53e4f855d93f6931df53a220a5fb374044328f9944`

An extra, missing, renamed, removed, reordered, differently hashed, or differently based file fails closed. Pack B3 does not issue this seal and does not mutate PR459.

No wildcard, general docs exception, arbitrary target, caller-defined policy, or default-safe token exists.

## Seal schema and canonical serialization

The JSON Schema at `schemas/founder-authorization-seal-v1.schema.json` rejects unknown fields and fixes exact types and constants. A seal binds:

- schema and seal type
- issuer repository, repository ID, workflow path, workflow commit, run ID and attempt
- Founder actor and issuance timestamp
- target repository ID, node ID, full name, PR number, exact head and branch, and base
- merge mode and freeze scope
- changed-file count, path-set digest, reviewed-scope digest, and policy payload digest
- fixed authorization provenance
- deterministic run/PR/head nonce
- deterministic artifact name
- canonical seal-body digest
- the requirement for artifact attestation

Canonical JSON recursively orders object keys by UTF-8 bytes, uses two-space JSON indentation, encodes UTF-8 without BOM, uses LF, and ends with one terminal LF.

A JSON document cannot contain its own exact-file hash without circularity. Accordingly, `artifact_sha256` is explicitly defined as SHA-256 of the canonical seal body with the `artifact_sha256` property omitted. The sidecar separately records SHA-256 of the exact final `founder-authorization-seal.json` bytes. Verification recomputes both digests.

## Artifact, attestation, and retention

The deterministic artifact name is:

```text
founder-seal-v1-pr-<PR_NUMBER>-<12_HEX_HEAD_PREFIX>-run-<RUN_ID>
```

It contains exactly:

- `founder-authorization-seal.json`
- `founder-authorization-seal.sha256`
- `issuance-summary.json`

The three files are attested with the pinned `actions/attest` action and uploaded under the deterministic name for 90 days. Every external action is pinned to a full immutable commit SHA.

The future B4 consumer must verify the attestation against `viona-global/viona-governance`, workflow identity and commit, exact sidecar, canonical schema, and seal-body digest. It must fail closed on missing, invalid, expired, ambiguous, or multiple matching artifacts. It must never fall back to caller-provided JSON. V1 consumers must reject seals more than 24 hours old at the merge-group event; a newer seal does not silently supersede an older one, and multiple valid matches require an explicit unambiguous selection rule implemented and reviewed in B4.

## Facts deliberately excluded

The seal does not certify or preserve:

- reviewer approval or permission
- review dismissal or changes-requested state
- review-thread resolution
- current CI/check state
- branch protection or ruleset state
- merge-queue membership or merge-group identity
- current base integration or mergeability

The future required `merge_group` workflow and GitHub native protection must evaluate those facts against the merge-time candidate. A seal alone cannot create a merge authorization check or permit merge.

## Current proof and limits

Pack B3 performs deterministic offline validation only. Tests cover Founder and issuer identity, fixed inputs, API failures, complete pagination, canonical digests, exact PR459 policy, bounded remediation paths, schema rejection, serialization, tamper detection, immutable action pins, minimal permissions, and zero target-write call paths.

Offline proof does not establish that a live workflow run will succeed, that an eligible independent reviewer exists, that PR459 or any other PR is merge-ready, that B4 will consume the artifact correctly, or that target migration and merge-queue enforcement are active. Those are later separately authorized gates.
