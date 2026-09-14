#!/usr/bin/env node

import { createHash } from "node:crypto";
import { appendFile, mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const AUTHORIZED_FOUNDER = "laoton80-del";
export const ISSUER_REPOSITORY = "viona-global/viona-governance";
export const ISSUER_REPOSITORY_ID = 1370004364;
export const ISSUER_WORKFLOW_PATH = ".github/workflows/founder-authorization-seal.yml";
export const ISSUER_MAIN_REF = "refs/heads/main";
export const TARGET_REPOSITORY = "laoton80-del/Ket-noi-eu";
export const TARGET_REPOSITORY_ID = 1213874552;
export const TARGET_REPOSITORY_NODE_ID = "R_kgDOSFpBeA";
export const TARGET_BASE_BRANCH = "master";
export const MERGE_MODE = "squash";
export const AUTHORIZATION_PROVENANCE = "FOUNDER_MANUAL_WORKFLOW_DISPATCH_V1";
export const REMEDIATION_FREEZE_SCOPE =
  "FREEZE_EXCEPTION_FOR_MERGE_GUARDRAIL_REMEDIATION_ONLY";
export const PR459_FREEZE_SCOPE =
  "FREEZE_EXCEPTION_FOR_PR459_OPERATING_PROTOCOL_V2_CANONICAL_PROMOTION_ONLY";
export const SCHEMA_VERSION = "viona.founder-authorization-seal/v1";
export const SEAL_TYPE = "FOUNDER_AUTHORIZATION_SEAL";
export const ISSUER_IDENTITY = "VIONA_FOUNDER_AUTHORIZATION_SEAL_WORKFLOW_V1";
export const PR459_NUMBER = 459;
export const PR459_HEAD_BRANCH =
  "docs/viona-operating-protocol-v2-canonical-promotion";
export const PR459_CANONICAL_PAYLOAD_DIGEST =
  "6a7e59d1b2948f16999bff53e4f855d93f6931df53a220a5fb374044328f9944";
export const MAX_FILE_PAGES = 50;
export const FILE_PAGE_SIZE = 100;

const SHA1_PATTERN = /^[0-9a-f]{40}$/;
const SHA256_PATTERN = /^[0-9a-f]{64}$/;
const POSITIVE_INTEGER_PATTERN = /^[1-9][0-9]*$/;
const RFC3339_MILLISECONDS_PATTERN =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const SUPPORTED_FILE_STATUSES = new Set([
  "added",
  "modified",
  "removed",
  "renamed",
]);
const ALLOWED_INPUT_KEYS = Object.freeze([
  "authorization_provenance",
  "freeze_scope",
  "merge_mode",
  "target_pr_number",
  "target_repository",
]);

export const PR459_EXPECTED_FILES = Object.freeze([
  Object.freeze({
    status: "added",
    path: "docs/ai-context/VIONA_CODEX_CANONICAL_ENTRYPOINT.md",
    sha256: "9ab7705adc748722432ba99f2cc9d51577dee6ec1e55a9ad73286518a110f843",
  }),
  Object.freeze({
    status: "modified",
    path: "docs/ai-context/VIONA_OPERATING_PROTOCOL.md",
    sha256: "a90c443e775bd82ca58f2b225957af9f21ffb787314fb7ce1fde48358c789d16",
  }),
  Object.freeze({
    status: "added",
    path: "docs/ai-context/archive/VIONA_OPERATING_PROTOCOL_V1.md",
    sha256: "9cfe4452f974a287e74e4bff5c987e8614178b501c2b7be05aca73e51dd4f657",
  }),
  Object.freeze({
    status: "added",
    path: "docs/design/evidence/codex-viona-operating-protocol-v2-reconcile-and-promote-v1/README.md",
    sha256: "3d971bca8d7b26bfe4858349fdd1142ef45f8cb656215041046470f0b2aad172",
  }),
  Object.freeze({
    status: "added",
    path: "docs/design/evidence/codex-viona-operating-protocol-v2-reconcile-and-promote-v1/RECONCILIATION_MATRIX.md",
    sha256: "c1c18c76bb6c19724b52ec0d059760fb81879ceb80f190ac2257653809150e05",
  }),
  Object.freeze({
    status: "added",
    path: "docs/design/evidence/codex-viona-operating-protocol-v2-reconcile-and-promote-v1/evidence-manifest.sha256",
    sha256: "0da50a50fd9aef6b66700e72369293654212bff82644cb30e0bff2b6f38e9f9d",
  }),
  Object.freeze({
    status: "added",
    path: "docs/design/evidence/codex-viona-operating-protocol-v2-reconcile-and-promote-v1/promotion-record.json",
    sha256: "31c6b3d53a6acd9c7e773aeeb5214e37fe99d5267ecab84644ef6874cb8d3408",
  }),
]);

export const REMEDIATION_ALLOWED_PATHS = Object.freeze([
  ".github/workflows/viona-merge-authorization-gate.yml",
  "scripts/viona-merge-authorization-gate.mjs",
  "scripts/test-viona-merge-authorization-gate.mjs",
  "scripts/viona-guarded-pr-merge.mjs",
  "scripts/test-viona-guarded-pr-merge.mjs",
  "docs/product/VIONA_PR459_EXACT_CANONICAL_DOCS_FREEZE_EXCEPTION_DESIGN.md",
  "docs/design/evidence/codex-pr459-exact-canonical-docs-freeze-exception-design-v1/README.md",
  "docs/design/evidence/codex-pr459-content-bound-one-shot-gate-implementation-v1/README.md",
]);

export const SEAL_FIELDS = Object.freeze([
  "schema_version",
  "seal_type",
  "issuer",
  "issuer_repository",
  "issuer_repository_id",
  "issuer_workflow_path",
  "issuer_workflow_commit_sha",
  "issuer_workflow_run_id",
  "issuer_workflow_run_attempt",
  "issuer_actor",
  "issued_at",
  "target_repository",
  "target_repository_id",
  "target_repository_node_id",
  "target_pr_number",
  "target_pr_head_sha",
  "target_pr_head_branch",
  "target_base_branch",
  "merge_mode",
  "freeze_scope",
  "changed_file_count",
  "changed_path_set_digest",
  "reviewed_scope_digest",
  "payload_digest",
  "authorization_provenance",
  "seal_nonce_or_unique_identifier",
  "artifact_name",
  "artifact_sha256",
  "attestation_expected",
]);

export class SealValidationError extends Error {
  constructor(code, message) {
    super(`${code}: ${message}`);
    this.name = "SealValidationError";
    this.code = code;
  }
}

function reject(code, message) {
  throw new SealValidationError(code, message);
}

function isPlainObject(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requirePlainObject(value, code, label) {
  if (!isPlainObject(value)) {
    reject(code, `${label} must be a plain object`);
  }
  return value;
}

function requireExactKeys(object, expectedKeys, code, label) {
  const actual = Object.keys(object).sort(compareUtf8);
  const expected = [...expectedKeys].sort(compareUtf8);
  if (actual.length !== expected.length) {
    reject(code, `${label} has an unexpected key count`);
  }
  for (let index = 0; index < expected.length; index += 1) {
    if (actual[index] !== expected[index]) {
      reject(code, `${label} contains missing or unknown fields`);
    }
  }
}

function requireExactString(value, expected, code, label) {
  if (typeof value !== "string" || value !== expected) {
    reject(code, `${label} must equal ${expected}`);
  }
  return value;
}

function requireNonEmptyString(value, code, label) {
  if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
    reject(code, `${label} must be a non-empty canonical string`);
  }
  return value;
}

function requirePositiveIntegerString(value, code, label) {
  if (typeof value !== "string" || !POSITIVE_INTEGER_PATTERN.test(value)) {
    reject(code, `${label} must be a canonical positive integer string`);
  }
  return value;
}

function requirePositiveSafeInteger(value, code, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    reject(code, `${label} must be a positive safe integer`);
  }
  return value;
}

function requireSha1(value, code, label) {
  if (typeof value !== "string" || !SHA1_PATTERN.test(value)) {
    reject(code, `${label} must be a lowercase 40-character Git SHA`);
  }
  return value;
}

function requireSha256(value, code, label) {
  if (typeof value !== "string" || !SHA256_PATTERN.test(value)) {
    reject(code, `${label} must be a lowercase SHA-256 digest`);
  }
  return value;
}

function requireBoolean(value, code, label) {
  if (typeof value !== "boolean") {
    reject(code, `${label} must be boolean`);
  }
  return value;
}

export function compareUtf8(left, right) {
  return Buffer.compare(Buffer.from(left, "utf8"), Buffer.from(right, "utf8"));
}

function stableValue(value) {
  if (Array.isArray(value)) {
    return value.map(stableValue);
  }
  if (isPlainObject(value)) {
    const output = {};
    for (const key of Object.keys(value).sort(compareUtf8)) {
      output[key] = stableValue(value[key]);
    }
    return output;
  }
  return value;
}

export function canonicalJson(value) {
  return `${JSON.stringify(stableValue(value), null, 2)}\n`;
}

export function sha256Hex(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function gitBlobSha(bytes) {
  const body = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  const prefix = Buffer.from(`blob ${body.length}\0`, "utf8");
  return createHash("sha1").update(prefix).update(body).digest("hex");
}

export function validateRepositoryPath(value, label = "repository path") {
  requireNonEmptyString(value, "INVALID_PATH", label);
  if (
    value.startsWith("/") ||
    value.includes("\\") ||
    value.includes("\0") ||
    value.includes("\t") ||
    value.includes("\n") ||
    value.includes("\r")
  ) {
    reject("INVALID_PATH", `${label} is not a canonical repository-relative path`);
  }
  const segments = value.split("/");
  if (segments.some((segment) => segment === "" || segment === "." || segment === "..")) {
    reject("INVALID_PATH", `${label} contains an invalid path segment`);
  }
  return value;
}

export function normalizeChangedFile(raw) {
  requirePlainObject(raw, "MALFORMED_FILE", "changed file");
  const status = requireNonEmptyString(raw.status, "MALFORMED_FILE", "file status");
  if (!SUPPORTED_FILE_STATUSES.has(status)) {
    reject("MALFORMED_FILE", `unsupported file status: ${status}`);
  }
  const filename = validateRepositoryPath(raw.filename, "filename");
  const sha = requireSha1(raw.sha, "MALFORMED_FILE", "file blob SHA");
  let previousFilename = "";
  if (status === "renamed") {
    previousFilename = validateRepositoryPath(raw.previous_filename, "previous filename");
    if (previousFilename === filename) {
      reject("MALFORMED_FILE", "renamed path must differ from its previous path");
    }
  } else if (
    raw.previous_filename !== undefined &&
    raw.previous_filename !== null &&
    raw.previous_filename !== ""
  ) {
    reject("MALFORMED_FILE", "previous_filename is only valid for renamed files");
  }
  return Object.freeze({ status, filename, previous_filename: previousFilename, sha });
}

export function normalizeChangedFiles(rawFiles) {
  if (!Array.isArray(rawFiles)) {
    reject("MALFORMED_FILE_INVENTORY", "changed-file inventory must be an array");
  }
  const normalized = rawFiles.map(normalizeChangedFile);
  const paths = new Set();
  for (const file of normalized) {
    if (paths.has(file.filename)) {
      reject("DUPLICATE_FILE", `duplicate changed path: ${file.filename}`);
    }
    paths.add(file.filename);
  }
  return normalized;
}

export function canonicalReviewedScopeRecords(files) {
  return normalizeChangedFiles(files)
    .map((file) => ({
      filename: file.filename,
      line: `${file.status}\t${file.filename}\t${file.previous_filename || ""}`,
    }))
    .sort((left, right) => compareUtf8(left.filename, right.filename))
    .map((record) => record.line);
}

export function computeReviewedScopeDigest(files) {
  return sha256Hex(Buffer.from(canonicalReviewedScopeRecords(files).join("\n"), "utf8"));
}

export function computeChangedPathSetDigest(files) {
  const normalized = normalizeChangedFiles(files);
  const paths = normalized.map((file) => file.filename).sort(compareUtf8);
  return sha256Hex(Buffer.from(paths.join("\n"), "utf8"));
}

export function computeCanonicalPayloadDigest(records) {
  if (!Array.isArray(records) || records.length === 0) {
    reject("MALFORMED_PAYLOAD", "payload records must be a non-empty array");
  }
  const seen = new Set();
  const lines = records.map((record) => {
    requirePlainObject(record, "MALFORMED_PAYLOAD", "payload record");
    const recordPath = validateRepositoryPath(record.path, "payload path");
    const digest = requireSha256(record.sha256, "MALFORMED_PAYLOAD", "payload SHA-256");
    if (seen.has(recordPath)) {
      reject("MALFORMED_PAYLOAD", `duplicate payload path: ${recordPath}`);
    }
    seen.add(recordPath);
    return `${recordPath}\t${digest}`;
  });
  lines.sort(compareUtf8);
  return sha256Hex(Buffer.from(lines.join("\n"), "utf8"));
}

export function validateWorkflowContext(environment) {
  requirePlainObject(environment, "INVALID_CONTEXT", "workflow environment");
  const actor = requireExactString(
    environment.GITHUB_ACTOR,
    AUTHORIZED_FOUNDER,
    "UNAUTHORIZED_ACTOR",
    "github.actor",
  );
  requireExactString(
    environment.GITHUB_TRIGGERING_ACTOR,
    actor,
    "TRIGGERING_ACTOR_MISMATCH",
    "github.triggering_actor",
  );
  requireExactString(
    environment.GITHUB_EVENT_NAME,
    "workflow_dispatch",
    "INVALID_TRIGGER",
    "github.event_name",
  );
  requireExactString(
    environment.GITHUB_REPOSITORY,
    ISSUER_REPOSITORY,
    "WRONG_ISSUER_REPOSITORY",
    "github.repository",
  );
  requireExactString(
    environment.GITHUB_REPOSITORY_ID,
    String(ISSUER_REPOSITORY_ID),
    "WRONG_ISSUER_REPOSITORY_ID",
    "github.repository_id",
  );
  requireExactString(
    environment.GITHUB_REPOSITORY_OWNER,
    "viona-global",
    "WRONG_ISSUER_OWNER",
    "github.repository_owner",
  );
  requireExactString(
    environment.GITHUB_REF,
    ISSUER_MAIN_REF,
    "UNTRUSTED_WORKFLOW_REF",
    "github.ref",
  );
  requireExactString(
    environment.GITHUB_REF_NAME,
    "main",
    "UNTRUSTED_WORKFLOW_REF",
    "github.ref_name",
  );
  requireExactString(
    environment.GITHUB_REF_TYPE,
    "branch",
    "UNTRUSTED_WORKFLOW_REF",
    "github.ref_type",
  );
  requireExactString(
    environment.GITHUB_REF_PROTECTED,
    "true",
    "UNPROTECTED_ISSUER_REF",
    "github.ref_protected",
  );
  const workflowRef = requireExactString(
    environment.GITHUB_WORKFLOW_REF,
    `${ISSUER_REPOSITORY}/${ISSUER_WORKFLOW_PATH}@${ISSUER_MAIN_REF}`,
    "WRONG_WORKFLOW_PATH",
    "github.workflow_ref",
  );
  const workflowSha = requireSha1(
    environment.GITHUB_WORKFLOW_SHA,
    "MALFORMED_WORKFLOW_SHA",
    "github.workflow_sha",
  );
  requireExactString(
    environment.GITHUB_SHA,
    workflowSha,
    "WORKFLOW_COMMIT_MISMATCH",
    "github.sha",
  );
  const runId = requirePositiveIntegerString(
    environment.GITHUB_RUN_ID,
    "MALFORMED_RUN_ID",
    "github.run_id",
  );
  requireExactString(
    environment.GITHUB_RUN_ATTEMPT,
    "1",
    "INVALID_RUN_ATTEMPT",
    "github.run_attempt",
  );
  return Object.freeze({
    actor,
    workflowRef,
    workflowSha,
    runId,
    runAttempt: 1,
  });
}

export function validateInputs(raw) {
  requirePlainObject(raw, "INVALID_INPUTS", "workflow inputs");
  requireExactKeys(raw, ALLOWED_INPUT_KEYS, "INVALID_INPUTS", "workflow inputs");
  const targetRepository = requireExactString(
    raw.target_repository,
    TARGET_REPOSITORY,
    "TARGET_NOT_ALLOWED",
    "target_repository",
  );
  const targetPrNumberText = requirePositiveIntegerString(
    raw.target_pr_number,
    "INVALID_PR_NUMBER",
    "target_pr_number",
  );
  const targetPrNumber = Number(targetPrNumberText);
  requirePositiveSafeInteger(targetPrNumber, "INVALID_PR_NUMBER", "target_pr_number");
  const freezeScope = requireNonEmptyString(
    raw.freeze_scope,
    "INVALID_FREEZE_SCOPE",
    "freeze_scope",
  );
  if (![REMEDIATION_FREEZE_SCOPE, PR459_FREEZE_SCOPE].includes(freezeScope)) {
    reject("INVALID_FREEZE_SCOPE", "freeze_scope is not an allowed V1 constant");
  }
  const mergeMode = requireExactString(
    raw.merge_mode,
    MERGE_MODE,
    "INVALID_MERGE_MODE",
    "merge_mode",
  );
  const provenance = requireExactString(
    raw.authorization_provenance,
    AUTHORIZATION_PROVENANCE,
    "INVALID_PROVENANCE",
    "authorization_provenance",
  );
  return Object.freeze({
    targetRepository,
    targetPrNumber,
    freezeScope,
    mergeMode,
    provenance,
  });
}

export function validateTargetRepository(raw) {
  requirePlainObject(raw, "MALFORMED_REPOSITORY", "target repository response");
  requireExactString(
    raw.full_name,
    TARGET_REPOSITORY,
    "TARGET_REPOSITORY_MISMATCH",
    "repository full_name",
  );
  const id = requirePositiveSafeInteger(raw.id, "MALFORMED_REPOSITORY", "repository id");
  const nodeId = requireNonEmptyString(
    raw.node_id,
    "MALFORMED_REPOSITORY",
    "repository node_id",
  );
  if (id !== TARGET_REPOSITORY_ID) {
    reject("TARGET_REPOSITORY_ID_MISMATCH", "repository id differs from the sealed B0 identity");
  }
  if (nodeId !== TARGET_REPOSITORY_NODE_ID) {
    reject("TARGET_REPOSITORY_ID_MISMATCH", "repository node_id differs from the sealed B0 identity");
  }
  requireExactString(raw.visibility, "public", "TARGET_NOT_PUBLIC", "repository visibility");
  requireExactString(
    raw.default_branch,
    TARGET_BASE_BRANCH,
    "TARGET_DEFAULT_BRANCH_MISMATCH",
    "repository default_branch",
  );
  requireBoolean(raw.archived, "MALFORMED_REPOSITORY", "repository archived");
  requireBoolean(raw.disabled, "MALFORMED_REPOSITORY", "repository disabled");
  if (raw.archived || raw.disabled) {
    reject("TARGET_REPOSITORY_INACTIVE", "target repository is archived or disabled");
  }
  return Object.freeze({
    id: TARGET_REPOSITORY_ID,
    nodeId: TARGET_REPOSITORY_NODE_ID,
    fullName: TARGET_REPOSITORY,
  });
}

export function validateTargetPullRequest(raw, inputs) {
  requirePlainObject(raw, "MALFORMED_PR", "pull request response");
  const number = requirePositiveSafeInteger(raw.number, "MALFORMED_PR", "pull request number");
  if (number !== inputs.targetPrNumber) {
    reject("PR_NUMBER_MISMATCH", "live pull request number differs from the requested subject");
  }
  requireExactString(raw.state, "open", "PR_NOT_OPEN", "pull request state");
  requireBoolean(raw.draft, "MALFORMED_PR", "pull request draft state");
  requireBoolean(raw.merged, "MALFORMED_PR", "pull request merged state");
  if (raw.draft) {
    reject("PR_IS_DRAFT", "draft pull requests cannot receive a V1 seal");
  }
  if (raw.merged) {
    reject("PR_ALREADY_MERGED", "merged pull requests cannot receive a seal");
  }
  const head = requirePlainObject(raw.head, "MALFORMED_PR", "pull request head");
  const base = requirePlainObject(raw.base, "MALFORMED_PR", "pull request base");
  const headRepo = requirePlainObject(head.repo, "MALFORMED_PR", "pull request head repository");
  const baseRepo = requirePlainObject(base.repo, "MALFORMED_PR", "pull request base repository");
  requireExactString(
    headRepo.full_name,
    TARGET_REPOSITORY,
    "CROSS_REPOSITORY_HEAD_NOT_ALLOWED",
    "pull request head repository",
  );
  requireExactString(
    baseRepo.full_name,
    TARGET_REPOSITORY,
    "BASE_REPOSITORY_MISMATCH",
    "pull request base repository",
  );
  const headSha = requireSha1(head.sha, "MALFORMED_PR", "pull request head SHA");
  const headBranch = requireNonEmptyString(head.ref, "MALFORMED_PR", "pull request head branch");
  const baseBranch = requireExactString(
    base.ref,
    TARGET_BASE_BRANCH,
    "BASE_BRANCH_MISMATCH",
    "pull request base branch",
  );
  const changedFileCount = requirePositiveSafeInteger(
    raw.changed_files,
    "MALFORMED_PR",
    "pull request changed_files",
  );
  return Object.freeze({
    number,
    headSha,
    headBranch,
    baseBranch,
    changedFileCount,
  });
}

function getHeader(headers, name) {
  if (headers === null || headers === undefined) {
    return null;
  }
  if (typeof headers.get === "function") {
    return headers.get(name);
  }
  if (isPlainObject(headers)) {
    const key = Object.keys(headers).find((candidate) => candidate.toLowerCase() === name.toLowerCase());
    return key ? headers[key] : null;
  }
  reject("MALFORMED_HEADERS", "API headers must expose get() or be a plain object");
}

export function parseNextFilePage(linkHeader, prNumber, currentPage) {
  if (linkHeader === null || linkHeader === undefined || linkHeader === "") {
    return null;
  }
  if (typeof linkHeader !== "string") {
    reject("MALFORMED_PAGINATION", "Link header must be a string");
  }
  const relations = new Map();
  for (const part of linkHeader.split(",")) {
    const match = /^\s*<([^>]+)>\s*;\s*rel="([a-z]+)"\s*$/.exec(part);
    if (!match) {
      reject("MALFORMED_PAGINATION", "Link header entry is malformed");
    }
    if (relations.has(match[2])) {
      reject("MALFORMED_PAGINATION", `duplicate Link relation: ${match[2]}`);
    }
    relations.set(match[2], match[1]);
  }
  if (!relations.has("next")) {
    return null;
  }
  let nextUrl;
  try {
    nextUrl = new URL(relations.get("next"));
  } catch {
    reject("MALFORMED_PAGINATION", "next-page URL is invalid");
  }
  const allowedPaths = new Set([
    `/repos/${TARGET_REPOSITORY}/pulls/${prNumber}/files`,
    `/repositories/${TARGET_REPOSITORY_ID}/pulls/${prNumber}/files`,
  ]);
  if (
    nextUrl.protocol !== "https:" ||
    nextUrl.host !== "api.github.com" ||
    !allowedPaths.has(nextUrl.pathname)
  ) {
    reject("MALFORMED_PAGINATION", "next-page URL escapes the allowlisted endpoint");
  }
  const keys = [...nextUrl.searchParams.keys()].sort(compareUtf8);
  if (keys.join(",") !== "page,per_page") {
    reject("MALFORMED_PAGINATION", "next-page URL has unexpected query parameters");
  }
  if (nextUrl.searchParams.get("per_page") !== String(FILE_PAGE_SIZE)) {
    reject("MALFORMED_PAGINATION", "next-page URL has the wrong page size");
  }
  const nextPageText = nextUrl.searchParams.get("page");
  if (!POSITIVE_INTEGER_PATTERN.test(nextPageText ?? "")) {
    reject("MALFORMED_PAGINATION", "next-page number is malformed");
  }
  const nextPage = Number(nextPageText);
  if (nextPage !== currentPage + 1) {
    reject("MALFORMED_PAGINATION", "next-page number is not sequential");
  }
  return nextPage;
}

export async function fetchAllChangedFiles(getPage, prNumber, expectedCount) {
  if (typeof getPage !== "function") {
    reject("INVALID_PAGINATOR", "getPage must be a function");
  }
  requirePositiveSafeInteger(prNumber, "INVALID_PR_NUMBER", "pull request number");
  requirePositiveSafeInteger(expectedCount, "MALFORMED_PR", "changed-file count");
  const collected = [];
  const visited = new Set();
  let page = 1;
  for (let requestCount = 0; requestCount < MAX_FILE_PAGES; requestCount += 1) {
    if (visited.has(page)) {
      reject("PAGINATION_CYCLE", "changed-file pagination repeated a page");
    }
    visited.add(page);
    const response = await getPage(page);
    requirePlainObject(response, "MALFORMED_FILE_PAGE", "changed-file page response");
    if (!Array.isArray(response.data)) {
      reject("MALFORMED_FILE_PAGE", "changed-file page data must be an array");
    }
    if (response.data.length > FILE_PAGE_SIZE) {
      reject("MALFORMED_FILE_PAGE", "changed-file page exceeds the configured page size");
    }
    collected.push(...response.data);
    const nextPage = parseNextFilePage(getHeader(response.headers, "link"), prNumber, page);
    if (nextPage === null) {
      if (collected.length !== expectedCount) {
        reject("INCOMPLETE_FILE_INVENTORY", "terminal pagination count differs from changed_files");
      }
      return normalizeChangedFiles(collected);
    }
    if (response.data.length === 0 || collected.length >= expectedCount) {
      reject("PAGINATION_CONTRADICTION", "next page conflicts with the accumulated file count");
    }
    page = nextPage;
  }
  reject("PAGINATION_LIMIT", "changed-file pagination limit reached before completion");
}

export function assertTargetReadApiPath(apiPath) {
  requireNonEmptyString(apiPath, "UNSAFE_API_PATH", "API path");
  let parsed;
  try {
    parsed = new URL(apiPath, "https://api.github.com");
  } catch {
    reject("UNSAFE_API_PATH", "API path is not a valid URL path");
  }
  if (parsed.origin !== "https://api.github.com" || !apiPath.startsWith("/")) {
    reject("UNSAFE_API_PATH", "API path must remain on api.github.com");
  }
  const repoPath = `/repos/${TARGET_REPOSITORY}`;
  if (parsed.pathname === repoPath && parsed.search === "") {
    return apiPath;
  }
  if (/^\/repos\/laoton80-del\/Ket-noi-eu\/pulls\/[1-9][0-9]*$/.test(parsed.pathname) && parsed.search === "") {
    return apiPath;
  }
  if (/^\/repos\/laoton80-del\/Ket-noi-eu\/pulls\/[1-9][0-9]*\/files$/.test(parsed.pathname)) {
    const keys = [...parsed.searchParams.keys()].sort(compareUtf8);
    if (
      keys.join(",") === "page,per_page" &&
      parsed.searchParams.get("per_page") === String(FILE_PAGE_SIZE) &&
      POSITIVE_INTEGER_PATTERN.test(parsed.searchParams.get("page") ?? "")
    ) {
      return apiPath;
    }
  }
  if (parsed.pathname.startsWith(`${repoPath}/contents/`)) {
    const keys = [...parsed.searchParams.keys()];
    if (keys.length === 1 && keys[0] === "ref" && SHA1_PATTERN.test(parsed.searchParams.get("ref") ?? "")) {
      return apiPath;
    }
  }
  reject("UNSAFE_API_PATH", "API path is outside the exact read-only target allowlist");
}

export async function githubApiGet(apiPath, fetchImplementation = globalThis.fetch) {
  assertTargetReadApiPath(apiPath);
  if (typeof fetchImplementation !== "function") {
    reject("API_UNAVAILABLE", "fetch implementation is unavailable");
  }
  let response;
  try {
    response = await fetchImplementation(`https://api.github.com${apiPath}`, {
      method: "GET",
      redirect: "error",
      headers: {
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "viona-founder-authorization-seal-v1",
      },
    });
  } catch (error) {
    reject("API_ERROR", `GitHub API request failed: ${error instanceof Error ? error.message : "unknown error"}`);
  }
  if (!response || typeof response.ok !== "boolean" || !Number.isInteger(response.status)) {
    reject("MALFORMED_API_RESPONSE", "GitHub API response metadata is malformed");
  }
  if (!response.ok) {
    reject("API_ERROR", `GitHub API returned HTTP ${response.status}`);
  }
  const contentType = getHeader(response.headers, "content-type");
  if (typeof contentType !== "string" || !contentType.toLowerCase().includes("json")) {
    reject("MALFORMED_API_RESPONSE", "GitHub API response is not JSON");
  }
  let data;
  try {
    const text = await response.text();
    data = JSON.parse(text);
  } catch {
    reject("MALFORMED_API_RESPONSE", "GitHub API JSON could not be parsed");
  }
  return { data, headers: response.headers };
}

function encodeContentPath(repositoryPath) {
  return repositoryPath.split("/").map(encodeURIComponent).join("/");
}

function decodeGitHubBase64(value) {
  if (typeof value !== "string") {
    reject("MALFORMED_CONTENT", "content payload must be a base64 string");
  }
  const compact = value.replace(/\n/g, "");
  if (compact.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(compact)) {
    reject("MALFORMED_CONTENT", "content payload is not canonical base64");
  }
  return Buffer.from(compact, "base64");
}

export function validateContentIdentity(raw, file, headSha) {
  requirePlainObject(raw, "MALFORMED_CONTENT", "content response");
  requireExactString(raw.type, "file", "MALFORMED_CONTENT", "content type");
  requireExactString(raw.encoding, "base64", "MALFORMED_CONTENT", "content encoding");
  requireExactString(raw.path, file.filename, "CONTENT_PATH_MISMATCH", "content path");
  requireExactString(raw.sha, file.sha, "CONTENT_BLOB_MISMATCH", "content blob SHA");
  requireSha1(headSha, "MALFORMED_PR", "pull request head SHA");
  const bytes = decodeGitHubBase64(raw.content);
  if (!Number.isSafeInteger(raw.size) || raw.size !== bytes.length) {
    reject("MALFORMED_CONTENT", "content size differs from decoded bytes");
  }
  if (gitBlobSha(bytes) !== file.sha) {
    reject("CONTENT_BLOB_MISMATCH", "decoded bytes do not match the Git blob SHA");
  }
  return Object.freeze({
    path: file.filename,
    sha256: sha256Hex(bytes),
    gitBlobSha: file.sha,
    byteLength: bytes.length,
  });
}

export function validateRemediationPolicy(pr, files) {
  if (!pr.headBranch.startsWith("fix/viona-") && !pr.headBranch.startsWith("codex/viona-")) {
    reject("REMEDIATION_BRANCH_NOT_ALLOWED", "remediation branch is outside the bounded V1 namespace");
  }
  const allowed = new Set(REMEDIATION_ALLOWED_PATHS);
  for (const file of files) {
    if (file.status === "renamed") {
      reject("REMEDIATION_SCOPE_NOT_ALLOWED", "renames are not allowed by the remediation V1 policy");
    }
    if (!allowed.has(file.filename)) {
      reject("REMEDIATION_SCOPE_NOT_ALLOWED", `path is outside the remediation allowlist: ${file.filename}`);
    }
  }
  return Object.freeze({ payloadDigest: null });
}

export function validatePr459Policy(pr, files, contentIdentities) {
  if (
    pr.number !== PR459_NUMBER ||
    pr.headBranch !== PR459_HEAD_BRANCH ||
    pr.baseBranch !== TARGET_BASE_BRANCH
  ) {
    reject("PR459_IDENTITY_MISMATCH", "PR459 exception subject identity does not match the pinned contract");
  }
  if (files.length !== PR459_EXPECTED_FILES.length) {
    reject("PR459_SCOPE_MISMATCH", "PR459 changed-file count differs from the pinned contract");
  }
  const expectedByPath = new Map(PR459_EXPECTED_FILES.map((file) => [file.path, file]));
  for (const file of files) {
    const expected = expectedByPath.get(file.filename);
    if (!expected || file.status !== expected.status || file.previous_filename !== "") {
      reject("PR459_SCOPE_MISMATCH", `PR459 scope record is not pinned: ${file.filename}`);
    }
  }
  if (!Array.isArray(contentIdentities) || contentIdentities.length !== PR459_EXPECTED_FILES.length) {
    reject("PR459_PAYLOAD_MISMATCH", "PR459 payload identity inventory is incomplete");
  }
  const identityByPath = new Map();
  for (const identity of contentIdentities) {
    requirePlainObject(identity, "PR459_PAYLOAD_MISMATCH", "content identity");
    const identityPath = validateRepositoryPath(identity.path, "content identity path");
    const digest = requireSha256(identity.sha256, "PR459_PAYLOAD_MISMATCH", "content identity SHA-256");
    if (identityByPath.has(identityPath)) {
      reject("PR459_PAYLOAD_MISMATCH", `duplicate content identity: ${identityPath}`);
    }
    identityByPath.set(identityPath, digest);
  }
  for (const expected of PR459_EXPECTED_FILES) {
    if (identityByPath.get(expected.path) !== expected.sha256) {
      reject("PR459_PAYLOAD_MISMATCH", `content digest differs for ${expected.path}`);
    }
  }
  const payloadDigest = computeCanonicalPayloadDigest(
    [...identityByPath].map(([recordPath, sha256]) => ({ path: recordPath, sha256 })),
  );
  if (payloadDigest !== PR459_CANONICAL_PAYLOAD_DIGEST) {
    reject("PR459_PAYLOAD_MISMATCH", "canonical PR459 payload digest differs from the pinned contract");
  }
  return Object.freeze({ payloadDigest });
}

export async function deriveAuthorizationSubject(inputs, apiGet = githubApiGet) {
  if (typeof apiGet !== "function") {
    reject("API_UNAVAILABLE", "apiGet must be a function");
  }
  const repoResponse = await apiGet(`/repos/${TARGET_REPOSITORY}`);
  requirePlainObject(repoResponse, "MALFORMED_API_RESPONSE", "repository API result");
  const repository = validateTargetRepository(repoResponse.data);
  const prResponse = await apiGet(`/repos/${TARGET_REPOSITORY}/pulls/${inputs.targetPrNumber}`);
  requirePlainObject(prResponse, "MALFORMED_API_RESPONSE", "pull request API result");
  const pr = validateTargetPullRequest(prResponse.data, inputs);
  const files = await fetchAllChangedFiles(
    async (page) =>
      apiGet(
        `/repos/${TARGET_REPOSITORY}/pulls/${inputs.targetPrNumber}/files?per_page=${FILE_PAGE_SIZE}&page=${page}`,
      ),
    inputs.targetPrNumber,
    pr.changedFileCount,
  );
  let policyResult;
  if (inputs.freezeScope === PR459_FREEZE_SCOPE) {
    const identities = [];
    for (const file of files) {
      if (file.status === "removed") {
        reject("PR459_PAYLOAD_MISMATCH", "PR459 policy cannot bind a removed payload file");
      }
      const contentResponse = await apiGet(
        `/repos/${TARGET_REPOSITORY}/contents/${encodeContentPath(file.filename)}?ref=${pr.headSha}`,
      );
      requirePlainObject(contentResponse, "MALFORMED_API_RESPONSE", "content API result");
      identities.push(validateContentIdentity(contentResponse.data, file, pr.headSha));
    }
    policyResult = validatePr459Policy(pr, files, identities);
  } else if (inputs.freezeScope === REMEDIATION_FREEZE_SCOPE) {
    policyResult = validateRemediationPolicy(pr, files);
  } else {
    reject("INVALID_FREEZE_SCOPE", "freeze scope has no policy implementation");
  }
  return Object.freeze({
    repository,
    pr,
    files,
    changedPathSetDigest: computeChangedPathSetDigest(files),
    reviewedScopeDigest: computeReviewedScopeDigest(files),
    payloadDigest: policyResult.payloadDigest,
  });
}

function requireCanonicalTimestamp(value) {
  if (typeof value !== "string" || !RFC3339_MILLISECONDS_PATTERN.test(value)) {
    reject("INVALID_TIMESTAMP", "issued_at must be canonical UTC RFC3339 with milliseconds");
  }
  const parsed = new Date(value);
  if (Number.isNaN(parsed.valueOf()) || parsed.toISOString() !== value) {
    reject("INVALID_TIMESTAMP", "issued_at is not a real canonical timestamp");
  }
  return value;
}

function canonicalSealBody(seal) {
  const body = { ...seal };
  delete body.artifact_sha256;
  return canonicalJson(body);
}

export function validateSealRecord(raw) {
  requirePlainObject(raw, "INVALID_SEAL", "seal");
  requireExactKeys(raw, SEAL_FIELDS, "INVALID_SEAL", "seal");
  requireExactString(raw.schema_version, SCHEMA_VERSION, "INVALID_SEAL", "schema_version");
  requireExactString(raw.seal_type, SEAL_TYPE, "INVALID_SEAL", "seal_type");
  requireExactString(raw.issuer, ISSUER_IDENTITY, "INVALID_SEAL", "issuer");
  requireExactString(raw.issuer_repository, ISSUER_REPOSITORY, "INVALID_SEAL", "issuer_repository");
  if (raw.issuer_repository_id !== ISSUER_REPOSITORY_ID) {
    reject("INVALID_SEAL", "issuer_repository_id differs from the pinned issuer");
  }
  requireExactString(raw.issuer_workflow_path, ISSUER_WORKFLOW_PATH, "INVALID_SEAL", "issuer_workflow_path");
  requireSha1(raw.issuer_workflow_commit_sha, "INVALID_SEAL", "issuer_workflow_commit_sha");
  requirePositiveIntegerString(raw.issuer_workflow_run_id, "INVALID_SEAL", "issuer_workflow_run_id");
  if (raw.issuer_workflow_run_attempt !== 1) {
    reject("INVALID_SEAL", "issuer_workflow_run_attempt must equal 1");
  }
  requireExactString(raw.issuer_actor, AUTHORIZED_FOUNDER, "INVALID_SEAL", "issuer_actor");
  requireCanonicalTimestamp(raw.issued_at);
  requireExactString(raw.target_repository, TARGET_REPOSITORY, "INVALID_SEAL", "target_repository");
  requirePositiveSafeInteger(raw.target_repository_id, "INVALID_SEAL", "target_repository_id");
  requireNonEmptyString(raw.target_repository_node_id, "INVALID_SEAL", "target_repository_node_id");
  requirePositiveSafeInteger(raw.target_pr_number, "INVALID_SEAL", "target_pr_number");
  requireSha1(raw.target_pr_head_sha, "INVALID_SEAL", "target_pr_head_sha");
  requireNonEmptyString(raw.target_pr_head_branch, "INVALID_SEAL", "target_pr_head_branch");
  requireExactString(raw.target_base_branch, TARGET_BASE_BRANCH, "INVALID_SEAL", "target_base_branch");
  requireExactString(raw.merge_mode, MERGE_MODE, "INVALID_SEAL", "merge_mode");
  if (![REMEDIATION_FREEZE_SCOPE, PR459_FREEZE_SCOPE].includes(raw.freeze_scope)) {
    reject("INVALID_SEAL", "freeze_scope is outside the V1 enum");
  }
  requirePositiveSafeInteger(raw.changed_file_count, "INVALID_SEAL", "changed_file_count");
  requireSha256(raw.changed_path_set_digest, "INVALID_SEAL", "changed_path_set_digest");
  requireSha256(raw.reviewed_scope_digest, "INVALID_SEAL", "reviewed_scope_digest");
  if (raw.payload_digest !== null) {
    requireSha256(raw.payload_digest, "INVALID_SEAL", "payload_digest");
  }
  if (raw.freeze_scope === PR459_FREEZE_SCOPE && raw.payload_digest !== PR459_CANONICAL_PAYLOAD_DIGEST) {
    reject("INVALID_SEAL", "PR459 seal must contain the pinned payload digest");
  }
  if (raw.freeze_scope === REMEDIATION_FREEZE_SCOPE && raw.payload_digest !== null) {
    reject("INVALID_SEAL", "remediation V1 seal payload_digest must be null");
  }
  requireExactString(
    raw.authorization_provenance,
    AUTHORIZATION_PROVENANCE,
    "INVALID_SEAL",
    "authorization_provenance",
  );
  requireNonEmptyString(raw.seal_nonce_or_unique_identifier, "INVALID_SEAL", "seal nonce");
  if (!/^founder-seal-v1-pr-[1-9][0-9]*-[0-9a-f]{12}-run-[1-9][0-9]*$/.test(raw.artifact_name)) {
    reject("INVALID_SEAL", "artifact_name is not canonical");
  }
  requireSha256(raw.artifact_sha256, "INVALID_SEAL", "artifact_sha256");
  requireBoolean(raw.attestation_expected, "INVALID_SEAL", "attestation_expected");
  if (!raw.attestation_expected) {
    reject("INVALID_SEAL", "attestation_expected must be true");
  }
  const expectedBodyDigest = sha256Hex(Buffer.from(canonicalSealBody(raw), "utf8"));
  if (raw.artifact_sha256 !== expectedBodyDigest) {
    reject("INVALID_SEAL", "artifact_sha256 does not match the canonical seal body");
  }
  return raw;
}

export function createSealBundle({ context, inputs, subject, issuedAt }) {
  requirePlainObject(context, "INVALID_CONTEXT", "validated context");
  requirePlainObject(inputs, "INVALID_INPUTS", "validated inputs");
  requirePlainObject(subject, "INVALID_SUBJECT", "authorization subject");
  const timestamp = requireCanonicalTimestamp(issuedAt);
  const artifactName = `founder-seal-v1-pr-${subject.pr.number}-${subject.pr.headSha.slice(0, 12)}-run-${context.runId}`;
  const sealCore = {
    schema_version: SCHEMA_VERSION,
    seal_type: SEAL_TYPE,
    issuer: ISSUER_IDENTITY,
    issuer_repository: ISSUER_REPOSITORY,
    issuer_repository_id: ISSUER_REPOSITORY_ID,
    issuer_workflow_path: ISSUER_WORKFLOW_PATH,
    issuer_workflow_commit_sha: context.workflowSha,
    issuer_workflow_run_id: context.runId,
    issuer_workflow_run_attempt: context.runAttempt,
    issuer_actor: context.actor,
    issued_at: timestamp,
    target_repository: subject.repository.fullName,
    target_repository_id: subject.repository.id,
    target_repository_node_id: subject.repository.nodeId,
    target_pr_number: subject.pr.number,
    target_pr_head_sha: subject.pr.headSha,
    target_pr_head_branch: subject.pr.headBranch,
    target_base_branch: subject.pr.baseBranch,
    merge_mode: inputs.mergeMode,
    freeze_scope: inputs.freezeScope,
    changed_file_count: subject.files.length,
    changed_path_set_digest: subject.changedPathSetDigest,
    reviewed_scope_digest: subject.reviewedScopeDigest,
    payload_digest: subject.payloadDigest,
    authorization_provenance: inputs.provenance,
    seal_nonce_or_unique_identifier:
      `v1:${subject.repository.id}:${subject.pr.number}:${subject.pr.headSha}:${context.runId}:${context.runAttempt}`,
    artifact_name: artifactName,
    attestation_expected: true,
  };
  const artifactBodyDigest = sha256Hex(Buffer.from(canonicalJson(sealCore), "utf8"));
  const seal = { ...sealCore, artifact_sha256: artifactBodyDigest };
  validateSealRecord(seal);
  const sealBytes = Buffer.from(canonicalJson(seal), "utf8");
  const sealFileDigest = sha256Hex(sealBytes);
  const sidecar = `${sealFileDigest}  founder-authorization-seal.json\n`;
  const summary = {
    schema_version: "viona.founder-authorization-seal-summary/v1",
    artifact_name: artifactName,
    seal_file: "founder-authorization-seal.json",
    seal_file_sha256: sealFileDigest,
    seal_body_sha256: artifactBodyDigest,
    target_repository: seal.target_repository,
    target_pr_number: seal.target_pr_number,
    target_pr_head_sha: seal.target_pr_head_sha,
    attestation_expected: true,
  };
  const summaryBytes = Buffer.from(canonicalJson(summary), "utf8");
  return Object.freeze({
    seal,
    sealBytes,
    sidecar,
    summary,
    summaryBytes,
    artifactName,
    sealFileDigest,
  });
}

export function verifySealBundle(bundle) {
  requirePlainObject(bundle, "INVALID_BUNDLE", "seal bundle");
  validateSealRecord(bundle.seal);
  if (!Buffer.isBuffer(bundle.sealBytes) || !Buffer.isBuffer(bundle.summaryBytes)) {
    reject("INVALID_BUNDLE", "bundle byte fields must be buffers");
  }
  const canonicalSealBytes = Buffer.from(canonicalJson(bundle.seal), "utf8");
  if (!bundle.sealBytes.equals(canonicalSealBytes)) {
    reject("SEAL_TAMPERED", "seal bytes are not the canonical serialization");
  }
  const digest = sha256Hex(bundle.sealBytes);
  const expectedSidecar = `${digest}  founder-authorization-seal.json\n`;
  if (bundle.sidecar !== expectedSidecar) {
    reject("SEAL_TAMPERED", "seal SHA-256 sidecar does not match exact JSON bytes");
  }
  requirePlainObject(bundle.summary, "INVALID_BUNDLE", "issuance summary");
  if (
    bundle.summary.seal_file_sha256 !== digest ||
    bundle.summary.seal_body_sha256 !== bundle.seal.artifact_sha256 ||
    bundle.summary.artifact_name !== bundle.seal.artifact_name ||
    bundle.summary.target_pr_head_sha !== bundle.seal.target_pr_head_sha
  ) {
    reject("SEAL_TAMPERED", "issuance summary does not match the seal");
  }
  if (!bundle.summaryBytes.equals(Buffer.from(canonicalJson(bundle.summary), "utf8"))) {
    reject("SEAL_TAMPERED", "issuance summary is not canonical");
  }
  return true;
}

export async function writeSealBundle(bundle, outputDirectory, githubOutputPath = null) {
  verifySealBundle(bundle);
  if (outputDirectory !== "out") {
    reject("UNSAFE_OUTPUT_PATH", "seal output directory must be exactly out");
  }
  const absoluteOutput = path.resolve(process.cwd(), outputDirectory);
  if (path.dirname(absoluteOutput) !== process.cwd()) {
    reject("UNSAFE_OUTPUT_PATH", "seal output directory escapes the checkout root");
  }
  await mkdir(absoluteOutput, { recursive: false });
  await writeFile(path.join(absoluteOutput, "founder-authorization-seal.json"), bundle.sealBytes, {
    flag: "wx",
  });
  await writeFile(path.join(absoluteOutput, "founder-authorization-seal.sha256"), bundle.sidecar, {
    encoding: "utf8",
    flag: "wx",
  });
  await writeFile(path.join(absoluteOutput, "issuance-summary.json"), bundle.summaryBytes, {
    flag: "wx",
  });
  if (githubOutputPath !== null) {
    requireNonEmptyString(githubOutputPath, "INVALID_GITHUB_OUTPUT", "GITHUB_OUTPUT");
    await appendFile(
      githubOutputPath,
      `artifact_name=${bundle.artifactName}\nseal_file_sha256=${bundle.sealFileDigest}\n`,
      { encoding: "utf8" },
    );
  }
}

function inputsFromEnvironment(environment) {
  return {
    target_repository: environment.INPUT_TARGET_REPOSITORY,
    target_pr_number: environment.INPUT_TARGET_PR_NUMBER,
    freeze_scope: environment.INPUT_FREEZE_SCOPE,
    merge_mode: environment.INPUT_MERGE_MODE,
    authorization_provenance: environment.INPUT_AUTHORIZATION_PROVENANCE,
  };
}

export async function runIssuance(environment = process.env, apiGet = githubApiGet, now = () => new Date()) {
  const context = validateWorkflowContext(environment);
  const inputs = validateInputs(inputsFromEnvironment(environment));
  const subject = await deriveAuthorizationSubject(inputs, apiGet);
  const issuedAt = now().toISOString();
  const bundle = createSealBundle({ context, inputs, subject, issuedAt });
  await writeSealBundle(bundle, environment.SEAL_OUTPUT_DIR, environment.GITHUB_OUTPUT ?? null);
  return bundle;
}

async function main() {
  if (process.argv.length !== 3 || process.argv[2] !== "issue") {
    reject("INVALID_COMMAND", "usage: node scripts/founder-authorization-seal.mjs issue");
  }
  await runIssuance();
  process.stdout.write("Founder Authorization Seal artifact created locally in the workflow workspace.\n");
}

const isDirectExecution = process.argv[1]
  ? fileURLToPath(import.meta.url) === path.resolve(process.argv[1])
  : false;

if (isDirectExecution) {
  main().catch((error) => {
    const message = error instanceof Error ? error.message : "UNKNOWN_ERROR: unknown failure";
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  });
}
