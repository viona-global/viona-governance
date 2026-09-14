#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  AUTHORIZATION_PROVENANCE,
  ISSUER_REPOSITORY,
  ISSUER_REPOSITORY_ID,
  ISSUER_WORKFLOW_PATH,
  PR459_CANONICAL_PAYLOAD_DIGEST,
  PR459_EXPECTED_FILES,
  PR459_FREEZE_SCOPE,
  PR459_HEAD_BRANCH,
  REMEDIATION_FREEZE_SCOPE,
  SEAL_FIELDS,
  TARGET_REPOSITORY,
  canonicalJson,
  computeCanonicalPayloadDigest,
  computeChangedPathSetDigest,
  computeReviewedScopeDigest,
  createSealBundle,
  fetchAllChangedFiles,
  gitBlobSha,
  githubApiGet,
  normalizeChangedFiles,
  parseNextFilePage,
  sha256Hex,
  validateContentIdentity,
  validateInputs,
  validatePr459Policy,
  validateRemediationPolicy,
  validateSealRecord,
  validateTargetPullRequest,
  validateTargetRepository,
  validateWorkflowContext,
  verifySealBundle,
  writeSealBundle,
} from "./founder-authorization-seal.mjs";

const SCRIPT_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(SCRIPT_DIRECTORY, "..");
const HEAD_SHA = "a".repeat(40);
const WORKFLOW_SHA = "b".repeat(40);
const FILE_SHA = "c".repeat(40);
const TARGET_REPOSITORY_ID = 1213874552;
const TARGET_NODE_ID = "R_kgDOSFpBeA";

function contextEnvironment(overrides = {}) {
  return {
    GITHUB_ACTOR: "laoton80-del",
    GITHUB_TRIGGERING_ACTOR: "laoton80-del",
    GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_REPOSITORY: ISSUER_REPOSITORY,
    GITHUB_REPOSITORY_ID: String(ISSUER_REPOSITORY_ID),
    GITHUB_REPOSITORY_OWNER: "viona-global",
    GITHUB_REF: "refs/heads/main",
    GITHUB_REF_NAME: "main",
    GITHUB_REF_TYPE: "branch",
    GITHUB_REF_PROTECTED: "true",
    GITHUB_WORKFLOW_REF:
      `${ISSUER_REPOSITORY}/${ISSUER_WORKFLOW_PATH}@refs/heads/main`,
    GITHUB_WORKFLOW_SHA: WORKFLOW_SHA,
    GITHUB_SHA: WORKFLOW_SHA,
    GITHUB_RUN_ID: "123456789",
    GITHUB_RUN_ATTEMPT: "1",
    ...overrides,
  };
}

function rawInputs(overrides = {}) {
  return {
    target_repository: TARGET_REPOSITORY,
    target_pr_number: "460",
    freeze_scope: REMEDIATION_FREEZE_SCOPE,
    merge_mode: "squash",
    authorization_provenance: AUTHORIZATION_PROVENANCE,
    ...overrides,
  };
}

function repositoryFixture(overrides = {}) {
  return {
    id: TARGET_REPOSITORY_ID,
    node_id: TARGET_NODE_ID,
    full_name: TARGET_REPOSITORY,
    visibility: "public",
    default_branch: "master",
    archived: false,
    disabled: false,
    ...overrides,
  };
}

function pullRequestFixture(overrides = {}) {
  return {
    number: 460,
    state: "open",
    draft: false,
    merged: false,
    changed_files: 1,
    head: {
      sha: HEAD_SHA,
      ref: "fix/viona-pr459-content-bound-one-shot-freeze-exception-gate",
      repo: { full_name: TARGET_REPOSITORY },
    },
    base: {
      ref: "master",
      repo: { full_name: TARGET_REPOSITORY },
    },
    ...overrides,
  };
}

function fileFixture(overrides = {}) {
  return {
    status: "modified",
    filename: "scripts/viona-merge-authorization-gate.mjs",
    sha: FILE_SHA,
    ...overrides,
  };
}

function validatedPr(overrides = {}) {
  const inputs = validateInputs(rawInputs());
  return validateTargetPullRequest(pullRequestFixture(overrides), inputs);
}

function validBundle() {
  const context = validateWorkflowContext(contextEnvironment());
  const inputs = validateInputs(rawInputs());
  const files = normalizeChangedFiles([fileFixture()]);
  const subject = {
    repository: validateTargetRepository(repositoryFixture()),
    pr: validatedPr(),
    files,
    changedPathSetDigest: computeChangedPathSetDigest(files),
    reviewedScopeDigest: computeReviewedScopeDigest(files),
    payloadDigest: null,
  };
  return createSealBundle({
    context,
    inputs,
    subject,
    issuedAt: "2026-09-14T12:34:56.789Z",
  });
}

function expectedPr459Files() {
  return normalizeChangedFiles(
    PR459_EXPECTED_FILES.map((expected, index) => ({
      status: expected.status,
      filename: expected.path,
      sha: (index + 1).toString(16).padStart(40, "0"),
    })),
  );
}

function expectedPr459Identities() {
  return PR459_EXPECTED_FILES.map((file) => ({ path: file.path, sha256: file.sha256 }));
}

function pr459PolicyPr(overrides = {}) {
  return {
    number: 459,
    headBranch: PR459_HEAD_BRANCH,
    baseBranch: "master",
    ...overrides,
  };
}

function nextLink(prNumber, page) {
  return `<https://api.github.com/repos/${TARGET_REPOSITORY}/pulls/${prNumber}/files?per_page=100&page=${page}>; rel="next"`;
}

function mockFetchResponse(status, data, headers = {}) {
  const normalizedHeaders = {
    "content-type": "application/json; charset=utf-8",
    ...headers,
  };
  return {
    ok: status >= 200 && status < 300,
    status,
    headers: {
      get(name) {
        const key = Object.keys(normalizedHeaders).find(
          (candidate) => candidate.toLowerCase() === name.toLowerCase(),
        );
        return key ? normalizedHeaders[key] : null;
      },
    },
    async text() {
      return JSON.stringify(data);
    },
  };
}

test("T01 correct Founder actor is a valid workflow candidate", () => {
  const context = validateWorkflowContext(contextEnvironment());
  assert.equal(context.actor, "laoton80-del");
});

test("T02 wrong workflow actor is rejected", () => {
  assert.throws(
    () => validateWorkflowContext(contextEnvironment({ GITHUB_ACTOR: "outsider" })),
    /UNAUTHORIZED_ACTOR/,
  );
});

test("T03 caller cannot spoof Founder through an extra input", () => {
  assert.throws(() => validateInputs(rawInputs({ founder: "laoton80-del" })), /INVALID_INPUTS/);
});

test("T04 wrong target repository is rejected", () => {
  assert.throws(
    () => validateInputs(rawInputs({ target_repository: "viona-global/other" })),
    /TARGET_NOT_ALLOWED/,
  );
});

test("T05 missing pull request API result fails closed", async () => {
  await assert.rejects(
    () =>
      githubApiGet(
        `/repos/${TARGET_REPOSITORY}/pulls/460`,
        async () => mockFetchResponse(404, { message: "Not Found" }),
      ),
    /API_ERROR.*404/,
  );
});

test("T06 closed pull request is rejected", () => {
  assert.throws(
    () => validateTargetPullRequest(pullRequestFixture({ state: "closed" }), validateInputs(rawInputs())),
    /PR_NOT_OPEN/,
  );
});

test("T07 merged pull request is rejected", () => {
  assert.throws(
    () => validateTargetPullRequest(pullRequestFixture({ merged: true }), validateInputs(rawInputs())),
    /PR_ALREADY_MERGED/,
  );
});

test("T08 draft pull request is rejected", () => {
  assert.throws(
    () => validateTargetPullRequest(pullRequestFixture({ draft: true }), validateInputs(rawInputs())),
    /PR_IS_DRAFT/,
  );
});

test("T09 malformed head SHA is rejected", () => {
  const fixture = pullRequestFixture();
  fixture.head.sha = "ABC";
  assert.throws(
    () => validateTargetPullRequest(fixture, validateInputs(rawInputs())),
    /MALFORMED_PR/,
  );
});

test("T10 unsupported merge mode is rejected", () => {
  assert.throws(() => validateInputs(rawInputs({ merge_mode: "merge" })), /INVALID_MERGE_MODE/);
});

test("T11 unsupported freeze scope is rejected", () => {
  assert.throws(() => validateInputs(rawInputs({ freeze_scope: "DOCS_ONLY" })), /INVALID_FREEZE_SCOPE/);
});

test("T12 wildcard freeze scope is rejected", () => {
  assert.throws(() => validateInputs(rawInputs({ freeze_scope: "*" })), /INVALID_FREEZE_SCOPE/);
});

test("T13 incomplete changed-file pagination is rejected", async () => {
  await assert.rejects(
    () => fetchAllChangedFiles(async () => ({ data: [fileFixture()], headers: {} }), 460, 2),
    /INCOMPLETE_FILE_INVENTORY/,
  );
});

test("T14 repeated or nonsequential pagination cursor is rejected", () => {
  assert.throws(() => parseNextFilePage(nextLink(460, 1), 460, 1), /MALFORMED_PAGINATION/);
});

test("T15 malformed changed-file record is rejected", () => {
  assert.throws(
    () => normalizeChangedFiles([fileFixture({ sha: null })]),
    /MALFORMED_FILE/,
  );
});

test("T16 deterministic reviewed-scope digest matches the canonical PR459 value", () => {
  assert.equal(
    computeReviewedScopeDigest(expectedPr459Files()),
    "5d242aeae7ad51dbf782dd7a38a2d94f314d1ce5410106dfb9c03aebc9802713",
  );
});

test("T17 path order permutations produce identical digests", () => {
  const files = expectedPr459Files();
  assert.equal(computeReviewedScopeDigest(files), computeReviewedScopeDigest([...files].reverse()));
  assert.equal(computeChangedPathSetDigest(files), computeChangedPathSetDigest([...files].reverse()));
});

test("T18 changed scope or bytes produce different digests", () => {
  const files = normalizeChangedFiles([fileFixture()]);
  const changedFiles = normalizeChangedFiles([
    fileFixture({ filename: "scripts/test-viona-merge-authorization-gate.mjs" }),
  ]);
  assert.notEqual(computeReviewedScopeDigest(files), computeReviewedScopeDigest(changedFiles));
  const payload = [{ path: "docs/a.md", sha256: "1".repeat(64) }];
  const changedPayload = [{ path: "docs/a.md", sha256: "2".repeat(64) }];
  assert.notEqual(computeCanonicalPayloadDigest(payload), computeCanonicalPayloadDigest(changedPayload));
});

test("T19 caller-supplied uppercase scope digest is not an accepted input", () => {
  assert.throws(
    () => validateInputs(rawInputs({ reviewed_scope_digest: "A".repeat(64) })),
    /INVALID_INPUTS/,
  );
});

test("T20 exact PR459 policy fixture passes and binds the expected payload digest", () => {
  const result = validatePr459Policy(
    pr459PolicyPr(),
    expectedPr459Files(),
    expectedPr459Identities(),
  );
  assert.equal(result.payloadDigest, PR459_CANONICAL_PAYLOAD_DIGEST);
  assert.equal(
    computeCanonicalPayloadDigest(expectedPr459Identities()),
    PR459_CANONICAL_PAYLOAD_DIGEST,
  );
});

test("T21 PR459 token with wrong PR number is rejected", () => {
  assert.throws(
    () =>
      validatePr459Policy(
        pr459PolicyPr({ number: 460 }),
        expectedPr459Files(),
        expectedPr459Identities(),
      ),
    /PR459_IDENTITY_MISMATCH/,
  );
});

test("T22 PR459 token with wrong branch is rejected", () => {
  assert.throws(
    () =>
      validatePr459Policy(
        pr459PolicyPr({ headBranch: "docs/other" }),
        expectedPr459Files(),
        expectedPr459Identities(),
      ),
    /PR459_IDENTITY_MISMATCH/,
  );
});

test("T23 PR459 token with an extra file is rejected", () => {
  const files = [
    ...expectedPr459Files(),
    ...normalizeChangedFiles([
      { status: "added", filename: "docs/extra.md", sha: "f".repeat(40) },
    ]),
  ];
  assert.throws(
    () => validatePr459Policy(pr459PolicyPr(), files, expectedPr459Identities()),
    /PR459_SCOPE_MISMATCH/,
  );
});

test("T24 PR459 token with a missing file is rejected", () => {
  assert.throws(
    () =>
      validatePr459Policy(
        pr459PolicyPr(),
        expectedPr459Files().slice(1),
        expectedPr459Identities().slice(1),
      ),
    /PR459_SCOPE_MISMATCH/,
  );
});

test("T25 PR459 token with a wrong payload digest is rejected", () => {
  const identities = expectedPr459Identities();
  identities[0] = { ...identities[0], sha256: "0".repeat(64) };
  assert.throws(
    () => validatePr459Policy(pr459PolicyPr(), expectedPr459Files(), identities),
    /PR459_PAYLOAD_MISMATCH/,
  );
});

test("T26 remediation scope cannot include product source", () => {
  const files = normalizeChangedFiles([
    { status: "modified", filename: "src/product.ts", sha: FILE_SHA },
  ]);
  assert.throws(() => validateRemediationPolicy(validatedPr(), files), /REMEDIATION_SCOPE_NOT_ALLOWED/);
});

test("T27 remediation scope cannot include runtime source", () => {
  const files = normalizeChangedFiles([
    { status: "modified", filename: "app/runtime.js", sha: FILE_SHA },
  ]);
  assert.throws(() => validateRemediationPolicy(validatedPr(), files), /REMEDIATION_SCOPE_NOT_ALLOWED/);
});

test("T28 artifact serialization is deterministic", () => {
  const first = validBundle();
  const second = validBundle();
  assert.deepEqual(first.sealBytes, second.sealBytes);
  assert.equal(first.sidecar, second.sidecar);
  assert.deepEqual(first.summaryBytes, second.summaryBytes);
});

test("T29 exact artifact digest detects tampering", () => {
  const bundle = validBundle();
  const tampered = { ...bundle, sealBytes: Buffer.concat([bundle.sealBytes, Buffer.from(" ")]) };
  assert.throws(() => verifySealBundle(tampered), /SEAL_TAMPERED/);
});

test("T30 unknown seal schema field is rejected", () => {
  const seal = { ...validBundle().seal, unknown: true };
  assert.throws(() => validateSealRecord(seal), /INVALID_SEAL/);
});

test("T31 missing required seal schema field is rejected", () => {
  const seal = { ...validBundle().seal };
  delete seal.target_pr_head_sha;
  assert.throws(() => validateSealRecord(seal), /INVALID_SEAL/);
});

test("T32 malformed seal schema field type is rejected", () => {
  const seal = { ...validBundle().seal, target_pr_number: "460" };
  assert.throws(() => validateSealRecord(seal), /INVALID_SEAL/);
});

test("T33 wrong issuer repository is rejected", () => {
  const seal = { ...validBundle().seal, issuer_repository: "viona-global/other" };
  assert.throws(() => validateSealRecord(seal), /INVALID_SEAL/);
});

test("T34 wrong workflow path is rejected", () => {
  const environment = contextEnvironment({
    GITHUB_WORKFLOW_REF:
      `${ISSUER_REPOSITORY}/.github/workflows/other.yml@refs/heads/main`,
  });
  assert.throws(() => validateWorkflowContext(environment), /WRONG_WORKFLOW_PATH/);
});

test("T35 wrong workflow commit identity is rejected", () => {
  assert.throws(
    () => validateWorkflowContext(contextEnvironment({ GITHUB_SHA: "d".repeat(40) })),
    /WORKFLOW_COMMIT_MISMATCH/,
  );
});

test("T36 workflow run attempt other than one is rejected", () => {
  assert.throws(
    () => validateWorkflowContext(contextEnvironment({ GITHUB_RUN_ATTEMPT: "2" })),
    /INVALID_RUN_ATTEMPT/,
  );
});

test("T37 target API 403 fails closed", async () => {
  await assert.rejects(
    () =>
      githubApiGet(
        `/repos/${TARGET_REPOSITORY}`,
        async () => mockFetchResponse(403, { message: "Forbidden" }),
      ),
    /API_ERROR.*403/,
  );
});

test("T38 target API 404 fails closed", async () => {
  await assert.rejects(
    () =>
      githubApiGet(
        `/repos/${TARGET_REPOSITORY}`,
        async () => mockFetchResponse(404, { message: "Not Found" }),
      ),
    /API_ERROR.*404/,
  );
});

test("T39 partial target API response fails schema validation", () => {
  assert.throws(
    () => validateTargetRepository({ full_name: TARGET_REPOSITORY }),
    /MALFORMED_REPOSITORY/,
  );
});

test("T40 source contains zero target-repository write API paths", async () => {
  const source = await readFile(path.join(REPOSITORY_ROOT, "scripts/founder-authorization-seal.mjs"), "utf8");
  const workflow = await readFile(
    path.join(REPOSITORY_ROOT, ".github/workflows/founder-authorization-seal.yml"),
    "utf8",
  );
  assert.equal((source.match(/method\s*:\s*["'](?:POST|PUT|PATCH|DELETE)["']/g) ?? []).length, 0);
  assert.equal((source.match(/\bgh\s+(?:api|pr|workflow|run)\b/g) ?? []).length, 0);
  assert.equal((source.match(/\bmutation\s*(?:\(|\{)/g) ?? []).length, 0);
  assert.equal((source.match(/\/check-runs|\/statuses|\/dispatches/g) ?? []).length, 0);
  assert.equal((workflow.match(/\bgh\s+(?:api|pr|workflow|run)\b/g) ?? []).length, 0);
});

test("T41 schema property inventory matches the implementation exactly", async () => {
  const schema = JSON.parse(
    await readFile(
      path.join(REPOSITORY_ROOT, "schemas/founder-authorization-seal-v1.schema.json"),
      "utf8",
    ),
  );
  assert.equal(schema.additionalProperties, false);
  assert.deepEqual([...schema.required].sort(), [...SEAL_FIELDS].sort());
  assert.deepEqual(Object.keys(schema.properties).sort(), [...SEAL_FIELDS].sort());
});

test("T42 complete multipage changed-file inventory succeeds", async () => {
  const files = Array.from({ length: 101 }, (_, index) =>
    fileFixture({ filename: `scripts/viona-merge-${String(index).padStart(3, "0")}.mjs` }),
  );
  const result = await fetchAllChangedFiles(
    async (page) =>
      page === 1
        ? { data: files.slice(0, 100), headers: { link: nextLink(460, 2) } }
        : { data: files.slice(100), headers: {} },
    460,
    101,
  );
  assert.equal(result.length, 101);
});

test("T43 pagination cannot redirect to another API host", () => {
  const link = '<https://evil.example/repos/laoton80-del/Ket-noi-eu/pulls/460/files?per_page=100&page=2>; rel="next"';
  assert.throws(() => parseNextFilePage(link, 460, 1), /MALFORMED_PAGINATION/);
});

test("T44 page-budget exhaustion while more pages exist fails closed", async () => {
  await assert.rejects(
    () =>
      fetchAllChangedFiles(
        async (page) => ({
          data: [fileFixture({ filename: `scripts/viona-merge-${page}.mjs` })],
          headers: { link: nextLink(460, page + 1) },
        }),
        460,
        100,
      ),
    /PAGINATION_LIMIT/,
  );
});

test("T45 content identity binds raw bytes, Git blob SHA, and SHA-256", () => {
  const bytes = Buffer.from("exact bytes\n", "utf8");
  const sha = gitBlobSha(bytes);
  const file = normalizeChangedFiles([fileFixture({ sha })])[0];
  const identity = validateContentIdentity(
    {
      type: "file",
      encoding: "base64",
      path: file.filename,
      sha,
      size: bytes.length,
      content: bytes.toString("base64"),
    },
    file,
    HEAD_SHA,
  );
  assert.equal(identity.sha256, sha256Hex(bytes));
});

test("T46 content API bytes that differ from the PR blob SHA are rejected", () => {
  const expected = Buffer.from("expected\n", "utf8");
  const actual = Buffer.from("changed\n", "utf8");
  const file = normalizeChangedFiles([fileFixture({ sha: gitBlobSha(expected) })])[0];
  assert.throws(
    () =>
      validateContentIdentity(
        {
          type: "file",
          encoding: "base64",
          path: file.filename,
          sha: file.sha,
          size: actual.length,
          content: actual.toString("base64"),
        },
        file,
        HEAD_SHA,
      ),
    /CONTENT_BLOB_MISMATCH/,
  );
});

test("T47 bounded remediation allowlist accepts a known governance surface", () => {
  const files = normalizeChangedFiles([fileFixture()]);
  assert.equal(validateRemediationPolicy(validatedPr(), files).payloadDigest, null);
});

test("T48 remediation branch outside the fixed VIONA namespace is rejected", () => {
  const files = normalizeChangedFiles([fileFixture()]);
  assert.throws(
    () => validateRemediationPolicy({ ...validatedPr(), headBranch: "feature/general" }, files),
    /REMEDIATION_BRANCH_NOT_ALLOWED/,
  );
});

test("T49 missing workflow input is rejected", () => {
  const inputs = rawInputs();
  delete inputs.target_pr_number;
  assert.throws(() => validateInputs(inputs), /INVALID_INPUTS/);
});

test("T50 malformed target repository response is rejected", () => {
  assert.throws(
    () => validateTargetRepository(repositoryFixture({ node_id: null })),
    /MALFORMED_REPOSITORY/,
  );
});

test("T51 cross-repository pull request head is rejected", () => {
  const fixture = pullRequestFixture();
  fixture.head.repo.full_name = "fork-owner/Ket-noi-eu";
  assert.throws(
    () => validateTargetPullRequest(fixture, validateInputs(rawInputs())),
    /CROSS_REPOSITORY_HEAD_NOT_ALLOWED/,
  );
});

test("T52 noncanonical issuance timestamp is rejected", () => {
  const bundle = validBundle();
  const seal = { ...bundle.seal, issued_at: "2026-09-14T12:34:56Z" };
  assert.throws(() => validateSealRecord(seal), /INVALID_TIMESTAMP/);
});

test("T53 output directory cannot be caller-selected", async () => {
  await assert.rejects(
    () => writeSealBundle(validBundle(), "../escape"),
    /UNSAFE_OUTPUT_PATH/,
  );
});

test("T54 workflow uses workflow_dispatch only and excludes authority-inheriting triggers", async () => {
  const workflow = await readFile(
    path.join(REPOSITORY_ROOT, ".github/workflows/founder-authorization-seal.yml"),
    "utf8",
  );
  assert.match(workflow, /^on:\r?\n  workflow_dispatch:/m);
  for (const forbidden of [
    /^\s*push:/m,
    /^\s*pull_request:/m,
    /^\s*pull_request_target:/m,
    /^\s*repository_dispatch:/m,
    /^\s*workflow_call:/m,
    /^\s*workflow_run:/m,
    /^\s*schedule:/m,
    /^\s*issue_comment:/m,
  ]) {
    assert.doesNotMatch(workflow, forbidden);
  }
});

test("T55 every external action reference is pinned by a full commit SHA", async () => {
  const workflow = await readFile(
    path.join(REPOSITORY_ROOT, ".github/workflows/founder-authorization-seal.yml"),
    "utf8",
  );
  const actionReferences = [...workflow.matchAll(/^\s*uses:\s*([^\s]+)$/gm)].map((match) => match[1]);
  assert.equal(actionReferences.length, 4);
  for (const reference of actionReferences) {
    assert.match(reference, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+@[0-9a-f]{40}$/);
  }
});

test("T56 workflow permission surface excludes repository and PR write scopes", async () => {
  const workflow = await readFile(
    path.join(REPOSITORY_ROOT, ".github/workflows/founder-authorization-seal.yml"),
    "utf8",
  );
  assert.match(workflow, /^  contents: read$/m);
  assert.match(workflow, /^  pull-requests: read$/m);
  assert.match(workflow, /^  id-token: write$/m);
  assert.match(workflow, /^  attestations: write$/m);
  assert.doesNotMatch(workflow, /^  (?:contents|pull-requests|checks|statuses|deployments|actions): write$/m);
});

test("T57 canonical JSON is stable across object insertion order", () => {
  assert.equal(canonicalJson({ z: 1, a: { y: 2, b: 3 } }), canonicalJson({ a: { b: 3, y: 2 }, z: 1 }));
});

test("T58 target API path allowlist rejects check-run creation endpoints", async () => {
  await assert.rejects(
    () => githubApiGet(`/repos/${TARGET_REPOSITORY}/check-runs`, async () => mockFetchResponse(200, {})),
    /UNSAFE_API_PATH/,
  );
});

test("T59 triggering actor must match the authorized workflow actor", () => {
  assert.throws(
    () =>
      validateWorkflowContext(
        contextEnvironment({ GITHUB_TRIGGERING_ACTOR: "github-actions[bot]" }),
      ),
    /TRIGGERING_ACTOR_MISMATCH/,
  );
});

test("T60 issuer branch must be protected main", () => {
  assert.throws(
    () => validateWorkflowContext(contextEnvironment({ GITHUB_REF_PROTECTED: "false" })),
    /UNPROTECTED_ISSUER_REF/,
  );
});

test("T61 shell-like pull-request input is rejected before use", () => {
  assert.throws(
    () => validateInputs(rawInputs({ target_pr_number: "460; echo unsafe" })),
    /INVALID_PR_NUMBER/,
  );
});

test("T62 workflow inputs are never directly interpolated inside shell run blocks", async () => {
  const workflow = await readFile(
    path.join(REPOSITORY_ROOT, ".github/workflows/founder-authorization-seal.yml"),
    "utf8",
  );
  const blocks = workflow.split(/\n\s{6}- name:/).filter((block) => block.includes("run: |"));
  assert.ok(blocks.length >= 2);
  for (const block of blocks) {
    const runBody = block.split("run: |")[1] ?? "";
    assert.doesNotMatch(runBody, /\$\{\{\s*inputs\./);
  }
});

test("T63 missing workflow actor fails closed", () => {
  assert.throws(
    () => validateWorkflowContext(contextEnvironment({ GITHUB_ACTOR: undefined })),
    /UNAUTHORIZED_ACTOR/,
  );
});

test("T64 malformed base64 target content fails closed", () => {
  const bytes = Buffer.from("exact bytes\n", "utf8");
  const sha = gitBlobSha(bytes);
  const file = normalizeChangedFiles([fileFixture({ sha })])[0];
  assert.throws(
    () =>
      validateContentIdentity(
        {
          type: "file",
          encoding: "base64",
          path: file.filename,
          sha,
          size: bytes.length,
          content: "%%%not-base64%%%",
        },
        file,
        HEAD_SHA,
      ),
    /MALFORMED_CONTENT/,
  );
});

test("T65 non-JSON target response fails closed", async () => {
  await assert.rejects(
    () =>
      githubApiGet(
        `/repos/${TARGET_REPOSITORY}`,
        async () => mockFetchResponse(200, {}, { "content-type": "text/plain" }),
      ),
    /MALFORMED_API_RESPONSE/,
  );
});

test("T66 GitHub numeric-repository pagination link is accepted only for the pinned ID", () => {
  const valid = '<https://api.github.com/repositories/1213874552/pulls/460/files?per_page=100&page=2>; rel="next"';
  const wrong = '<https://api.github.com/repositories/999/pulls/460/files?per_page=100&page=2>; rel="next"';
  assert.equal(parseNextFilePage(valid, 460, 1), 2);
  assert.throws(() => parseNextFilePage(wrong, 460, 1), /MALFORMED_PAGINATION/);
});

test("T67 recreated target slug with a different repository ID is rejected", () => {
  assert.throws(
    () => validateTargetRepository(repositoryFixture({ id: 999 })),
    /TARGET_REPOSITORY_ID_MISMATCH/,
  );
});
