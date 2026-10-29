# Step 5: Elicitation Technique

## Selected technique

**Technique:** Threat-driven derivation (no live stakeholder elicitation).

Concretely:

1. **Each finding in step 4 is mapped to one or more security requirements** (SRs) or environmental assumptions (EAs).
2. **Findings whose response is "documented limitation"** produce documentation requirements rather than code-level SRs.
3. **Findings whose root cause is integrator behaviour** produce environmental assumptions plus, where feasible, library-side guards that make the unsafe configuration awkward to reach (compile-time warnings, generator defaults).
4. **STRIDE acted as the checklist during step 4** — re-applied here to verify no category is missing requirements.

## Rationale

A library has no end-user stakeholders to interview. The conventional SQUARE elicitation techniques (structured interviews, ARM, IBIS, workshops) assume a system with operators, regulators, or domain experts on the receiving end of the assessment. For `ash_envelope`:

- The **maintainer** is the assessor and the requirements owner.
- The **integrator** is the requirements-bearing audience but is not a single identifiable party — they consume the requirements as documentation when they evaluate the library.
- The **data subjects** are not reachable for elicitation and are represented indirectly through the regulatory regime (GDPR, sectoral rules) baked into the damage-potential premise (step 4).

Given this, the methodologically clean approach is to derive requirements **directly from the rated threats**, with the rated risk level serving as the prioritisation signal in step 8.

Two minor secondary techniques inform the result:

- **Documentation review** — the existing `documentation/topics/how-envelope-encryption-works.md`, the moduledocs of `AshEnvelope`, `AshEnvelope.KeyGrants`, the `AshEnvelope.BlobIO.KeyManagers` modules, and `AshEnvelope.Reconcile`, and the design proposal under `documentation/proposals/` already encode many of the library's intended security properties. Requirements are derived to be consistent with, and verifiable against, those documents.
- **Code review** — the public API surface (the modules listed in step 3) was read to ensure each requirement is **verifiable**: either by a test the maintainer can write, or by reading a single piece of code.

## Participants

| Name / role | Stakeholder type | Contribution |
|---|---|---|
| Marc Nickert | Maintainer | Assessor; final decisions on scope, premise, and requirement wording. |
| Downstream integrator (represented by the documentation audience) | Owner (vicarious) | Receives the requirements as posture documentation; can raise issues against them via the GitHub repository. |
| Regulator (vicarious, via GDPR / sectoral rules) | Regulator | Damage-potential premise (step 4) and EA2/EA3 reflect the regulatory baseline. |

## Schedule

| Date | Activity | Output |
|---|---|---|
| 2026-05-11 | Step 1+2: definitions and security goals | `01_definitions.md`, `02_security_goals.md` |
| 2026-05-11 | Step 3: artifacts (architecture, data flows, misuse cases) | `03_artifacts.md` |
| 2026-05-12 | Step 4: damage potential, RAP scoring, risk matrix | `04_risk_assessment.md` |
| 2026-05-12 | Step 5: elicitation technique (this document) | `05_elicitation.md` |
| 2026-05-12 | Step 6: derive SRs and EAs from rated threats | `06_security_requirements.md` |
| 2026-05-12 | Step 7: categorize SRs (system / software / architectural constraint) | `07_categorization.md` |
| 2026-05-12 | Step 8: prioritize SRs from risk × category | `08_prioritization.md` |
| 2026-05-12 | Step 9: inspect SRs (ambiguity, traceability, testability) | `09_inspection.md` |
| 2026-05-12 | Finalize: overview + traceability matrix | `00_overview.md`, `traceability_matrix.md` |
| 2026-10-29 | Review pass: map the October 2026 code-review findings and the PR #14 fixes onto existing threats, SRs and controls; re-rate T6; record open items | `04_risk_assessment.md`, `06_security_requirements.md`, `07_categorization.md`, `08_prioritization.md`, `09_inspection.md`, `traceability_matrix.md`, `00_overview.md` |
