# Pack B3 Founder Authorization Seal V1 implementation evidence

## Classification

```text
PACK_ID=VIONA.GOVERNANCE.GITHUB_ORGANIZATION_MERGE_QUEUE.PACK_B3.FOUNDER_AUTHORIZATION_SEAL_WORKFLOW_IMPLEMENTATION.V1
AUTHORIZATION_PROVENANCE=APPROVE_VIONA_PACK_B3_FOUNDER_AUTHORIZATION_SEAL_WORKFLOW_IMPLEMENTATION
IMPLEMENTATION_STATE=OFFLINE_LOGIC_VERIFIED_PENDING_INDEPENDENT_REVIEW
LIVE_FOUNDER_SEAL_ISSUED=NO
WORKFLOW_DISPATCHED=NO
GOVERNANCE_MAIN_MERGED=NO
CENTRAL_GOVERNANCE_REPOSITORY_FINAL_TRUST_ACTIVE=NO
GLOBAL_FREEZE_STATE=ACTIVE
MIGRATION_FREEZE_ACTIVE=YES
```

This evidence records the candidate on branch `feat/founder-authorization-seal-v1`, created from governance `main` commit `e9bf1571e02ff803f0018c2e08afa471921fb323`. It does not claim live workflow execution, artifact upload, attestation issuance, merge authority, PR459 readiness, or target-governance activation.

## Candidate content identities

SHA-256 is over the exact working-tree file bytes validated before commit:

```text
b852ddf88abd755e27d3d08aef9cac58aa78d0d6703d6a052e4de4f93a0f1199  .github/workflows/founder-authorization-seal.yml
338d166ed5701e5fdea46121a3ca1d124c986f707596ec432998739912aa8636  scripts/founder-authorization-seal.mjs
2924d386839866b35b6847846cad8e0e7db28c975af86e13b8f83812184fcdc0  schemas/founder-authorization-seal-v1.schema.json
4a2df1f6294f52c00a959109fa6c683b4fd8262573565f2befa8173a0b9d5e2d  scripts/test-founder-authorization-seal.mjs
8555be71bb81a5c256343e80ee2790f6c0736a97ca7d007426e4d1b19fcfa062  docs/FOUNDER_AUTHORIZATION_SEAL_V1.md
```

The evidence README intentionally does not self-hash. Final staged Git blob identities and the commit identity are verified separately before publication.

## Workflow security surface

```text
TRIGGERS=workflow_dispatch_ONLY
AUTHORIZED_FOUNDER=laoton80-del
TRIGGERING_ACTOR_MUST_MATCH=YES
ISSUER_REPOSITORY=viona-global/viona-governance
ISSUER_REPOSITORY_ID=1370004364
ISSUER_REF=refs/heads/main
ISSUER_REF_MUST_BE_PROTECTED=YES
RUN_ATTEMPT_REQUIRED=1
TARGET_REPOSITORY=laoton80-del/Ket-noi-eu
TARGET_REPOSITORY_ID=1213874552
TARGET_REPOSITORY_NODE_ID=R_kgDOSFpBeA
TARGET_API_AUTHENTICATION=NONE_PUBLIC_READ_ONLY
TARGET_API_METHODS=GET_ONLY
CALLER_SUPPLIED_HEAD_SHA_ALLOWED=NO
CALLER_SUPPLIED_SCOPE_DIGEST_ALLOWED=NO
CALLER_DEFINED_FOUNDER_ALLOWED=NO
CALLER_DEFINED_POLICY_ALLOWED=NO
```

Workflow permissions:

```text
contents=read
pull-requests=read
id-token=write
attestations=write
contents_write=NO
pull_requests_write=NO
checks_write=NO
statuses_write=NO
actions_write=NO
deployments_write=NO
packages_write=NO
```

Immutable external action pins:

```text
actions/checkout@11d5960a326750d5838078e36cf38b85af677262
actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020
actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6
actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02
```

The action commits were resolved read-only from their current major-version Git refs on 2026-09-14. GitHub's current documentation states that artifact attestations are available for public repositories on GitHub Free and identifies `contents: read`, `id-token: write`, and `attestations: write` as the required provenance permissions: <https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations>.

## Deterministic validation

Final local commands:

```text
node --check scripts/founder-authorization-seal.mjs
node --check scripts/test-founder-authorization-seal.mjs
node -e JSON_SCHEMA_PARSE
node --test scripts/test-founder-authorization-seal.mjs
git diff --check (after explicit staging)
```

Final test result before evidence creation:

```text
SECURITY_TESTS_TOTAL=67
SECURITY_TESTS_PASS=67
SECURITY_TESTS_FAIL=0
```

The suite includes positive, negative, malformed-input, pagination, and tamper cases for:

- exact Founder, triggering actor, issuer repository, issuer branch, workflow path, workflow SHA, run ID, and first-attempt provenance
- fixed target, merge mode, freeze scopes, provenance, and strict input inventory
- open, non-draft, unmerged, same-repository PR identity at an exact head and base
- complete REST changed-file pagination, count agreement, cursor safety, host/path allowlisting, duplicate rejection, and page-limit failure
- canonical path-set, reviewed-scope, raw payload, Git blob, JSON, seal-body, and exact-file digest behavior
- exact seven-file PR459 status/path/hash contract and canonical payload digest
- explicit merge-guardrail remediation path allowlist and product/runtime rejection
- schema missing-field, unknown-field, type, constant, and timestamp rejection
- artifact byte and sidecar tamper detection
- shell-like input rejection and absence of direct workflow-input interpolation in shell blocks
- dispatch-only trigger, minimal permissions, immutable action pins, and zero target mutation paths

## Static target-mutation audit

```text
TARGET_REPO_WRITE_API_PATHS=0
TARGET_REPO_MUTATING_GH_CLI_COMMANDS=0
TARGET_REPO_MUTATING_GRAPHQL_OPERATIONS=0
TARGET_REPO_WORKFLOW_DISPATCH_PATHS=0
TARGET_REPO_CHECK_OR_STATUS_CREATION_PATHS=0
```

The implementation's target client admits only exact public GitHub REST read paths and fixes the request method to `GET`. The governance workflow can write only its own run artifact and attestation if later dispatched under separate authority.

## Seal semantics

The seal certifies frozen repository, PR, head, base, merge-mode, freeze-scope, changed-path, reviewed-scope, optional special-policy payload, Founder provenance, and trusted-workflow facts. It excludes mutable review, reviewer-permission, conversation, CI, protection, queue, base-integration, mergeability, and merge facts.

Canonical JSON uses stable UTF-8 key ordering, LF, no BOM, and one terminal newline. `artifact_sha256` hashes the canonical seal body with that field omitted to avoid self-hash circularity. The SHA-256 sidecar hashes the exact final seal JSON bytes. The future B4 consumer must verify both plus GitHub artifact attestation.

## Known limitations and later gates

- The workflow has not run on GitHub. Offline logic and static workflow structure are proven; hosted-runtime behavior is not yet proven.
- No artifact or attestation exists, and no live Founder seal has been issued.
- The target slug, numeric ID, and node ID are pinned to the Pack B0 pre-transfer identity. Repository transfer requires a separately reviewed issuer update after identity revalidation.
- Public unauthenticated target reads are subject to GitHub's public API rate limits. Rate limiting fails closed; there is no permissive fallback.
- The workflow requires protected `main` and therefore cannot issue from this feature branch.
- B4 must implement fail-closed seal discovery, uniqueness, age, attestation, and merge-group association checks. This candidate does not implement a consumer.
- The defined V1 consumer lifetime is 24 hours from `issued_at`; enforcement belongs to B4.
- Multiple candidate seals do not silently supersede one another. Ambiguity must fail closed in B4.
- An independent eligible reviewer is not currently proven. Branch protection must remain intact.
- PR459 and PR460 remain frozen and unchanged. Neither is claimed merge-ready.
- GitHub Team, target transfer, target rulesets, merge queue, required workflows, and sacrificial validation remain later separately authorized work.

## Remote-effect statement

Pack B3 may publish this exact candidate branch and open one protected pull request after final revalidation. It does not authorize merge, workflow dispatch, live seal issuance, target repository mutation, billing, permissions, branch-protection changes, transfer, or deployment.
