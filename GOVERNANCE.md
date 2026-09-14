# Governance

## Purpose

This repository is reserved for reviewed VIONA governance contracts, authorization-seal logic, merge-group validation, and deterministic governance evidence.

## Bootstrap law

The global VIONA freeze remains active. The initial bootstrap code owner is laoton80-del. No additional reviewer, team, collaborator, application, or bypass actor is authorized by Pack B2.

Future Founder Seal and merge-group workflows belong to separately authorized Packs B3 and B4. Until those packs are implemented and independently validated, this repository is not an active source of merge authority.

## Security rules

- Fail closed on missing, malformed, ambiguous, stale, or unverifiable authority.
- Bind authority to exact repository, pull request, head, base, merge mode, and reviewed scope as applicable.
- Never accept caller-defined free text as authority.
- Use least-privilege workflow permissions.
- Preserve one writer per workspace.
- Record deterministic content identities and evidence.
- Require separate authority for repository transfer, permission changes, rulesets, workflow activation, merge, and deployment.
- Do not store product code, runtime code, secrets, deploy credentials, or customer data here.

## Change control

Changes must use protected pull requests and independent approval under the active repository protection. Repository existence alone does not release any freeze or authorize changes in another repository.
