# Traceability Matrix

End-to-end mapping from assets → security goals → threats → requirements.

## Asset → Security goal

|  | SG1 | SG2 | SG3 | SG4 | SG5 | SG6 | SG7 | SG8 | SG9 |
|---|---|---|---|---|---|---|---|---|---|
| A1 Plaintext | ✓ | ✓ | | ✓ | | ✓ | ✓ | ✓ | |
| A2 DEK | | | ✓ | | | ✓ | | | |
| A3 Principal priv key | | | ✓ | | | | ✓ | | |
| A4 Wrapped DEK row | | ✓ | | ✓ | ✓ | | ✓ | | |
| A5 Ciphertext | ✓ | ✓ | | | | ✓ | | | |
| A6 Grant metadata | | | | ✓ | ✓ | ✓ | | ✓ | |
| A7 Grant requests | | | | ✓ | | | | ✓ | |
| A8 Reputation | | | | | | ✓ | | | ✓ |
| A9 Ephemeral grant row | ✓ | ✓ | ✓ | | | ✓ | ✓ | | |
| A10 Env seal key | ✓ | | ✓ | | | ✓ | ✓ | | |
| A11 Storage-service credentials | ✓ | ✓ | ✓ | | | | ✓ | | |

## Security goal → Threat

T1 (`:simple`-mode DBA disclosure) retired in v0.3.0. T9 (proxy bypass) returned
to scope in v0.4-dev with the ash_storage feature integration.

|  | T2 | T3 | T4 | T6 | T7 | T8 | T9 | T10 | T12 | T13 | T14 | T15 | T16 | T17 | T18 | T19 | T20 | T21 | T22 | T23 | T24 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| SG1 | ✓ | ✓ | | | | | ✓ | | | | | ✓ | | | ✓ | | ✓ | | | | ✓ |
| SG2 | ✓ | | ✓ | | | | | | | | | | | | ✓ | | | | ✓ | | |
| SG3 | | ✓ | | | ✓ | ✓ | | | | | | ✓ | | ✓ | ✓ | | | ✓ | | | ✓ |
| SG4 | | | | ✓ | | | ✓ | ✓ | | | | | | | | ✓ | ✓ | | | | |
| SG5 | | | | ✓ | | | | | | | | | | | | | | | | | |
| SG6 | | | | | | | | | ✓ | ✓ | | ✓ | | ✓ | ✓ | | | | ✓ | | |
| SG7 | | ✓ | | | | | ✓ | ✓ | | | | ✓ | | ✓ | ✓ | ✓ | | | | | |
| SG8 | | | | | | | | | ✓ | | | | ✓ | | | ✓ | | | | ✓ | |
| SG9 | | | | | | | | | | | ✓ | | | ✓ | ✓ | | ✓ | | | | ✓ |

## Threat → Requirement / Assumption

SR1, SR11, SR12, SR18 and EA7 are retired in v0.3.0 (code paths removed). SR32 (proxy-route generator) was added in v0.4-dev and covers T9 alongside SR31; not shown as a separate column here — see the combined view below.

|  | SR2 | SR3 | SR4 | SR5 | SR6 | SR7 | SR8 | SR9 | SR10 | SR13 | SR14 | SR15 | SR16 | SR17 | SR19 | SR20 | SR21 | SR22 | SR23 | SR24 | SR25 | SR26 | SR27 | SR28 | SR29 | SR30 | SR31 | EA1 | EA2 | EA3 | EA4 | EA5 | EA6 | EA8 | EA9 | EA10 | EA11 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| T2 | ✓ | ✓ | ✓ | | | | | | | | | | | | | | | | | | | | | | | | | | | ✓ | | |
| T3 | | | | ✓ | ✓ | | | | | | | | | | | | | | | | | | | | ✓ | | | | | | | |
| T4 | | | | | | ✓ | | | | | | | | | | | | | | | | | | | | | | | | | | |
| T6 | | | | | | | ✓ | | | | | | | | | | | | | | | | | | | ✓ | | | | | | |
| T7 | | | | | | | | ✓ | | | | | | | | | | | | | | | | | | | | | ✓ | | | |
| T8 | | | | | | | | | ✓ | | | | | | | | | | | | | | | | | | | | | | | |
| T10 | | | | | | | | | | ✓ | ✓ | | | | | | | | | | | | | ✓ | | ✓ | | | | | | |
| T12 | | | | | | | | | | | | ✓ | | | | | | | | | | | | | | | | | | | | |
| T13 | | | | | | | | | | | | | ✓ | | | | | | | | | | | | | | | | | | | |
| T14 | | ✓ | ✓ | | | | | | | | | | | ✓ | | | | | | | | | | | | | | | | ✓ | | |
| T15 | | | | | | | | | | | | | | | ✓ | | | | | | | | | | | | | | | | ✓ | |
| T16 | | | | | | | | | | | | | | | | ✓ | | | | | | | | | | | | | | | | |
| T17 | | | | | | | | | | | | | | | | | ✓ | ✓ | | ✓ | | ✓ | | | | | | | | | | ✓ |
| T18 | | | | | | | | | | | | | | | | | ✓ | ✓ | | ✓ | ✓ | ✓ | | | | | | | | | | ✓ |
| T19 | | | | | | | | | | | | | | | | | | | ✓ | | | | | | | | | | | | | |
| T20 | | | | | | | | | | | | | | | | | | | | | | | ✓ | | | ✓ | | | | | | |
| T9  | | | | | | | | | | | | | | | | | | | | | | | | | | ✓ | | | ✓ | | | |
| T21 | | | | | | | | | | | | | | | | | | | | | | | | | | ✓ | | | | ✓ | | |
| T22 | | | | | | | | | | | | | | | | | | | | | | | | | | ✓ | | | | | | |
| T23 | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | | |
| T24 | | | | | | | | | | | | | | | | | | | | | | | | | | | ✓ | | | | | ✓ |

## Combined view

| Req. | Goal(s) | Threat(s) | Asset(s) | Risk treated | Priority |
|---|---|---|---|---|---|
| SR2 | SG6, SG9 | T2 | A1, A8 | Tolerable | P1 |
| SR3 | SG1, SG2, SG6 | T2, T14 | A1, A2 | Tolerable | P1 |
| SR4 | SG6 | T2, T14 | A2 | defence in depth | P3 |
| SR5 | SG3, SG7 | T3 | A3 | Inacceptable → Undesirable (when scaffolds used) | P1 |
| SR6 | SG3, SG9 | T3 | A3 | Inacceptable (documented) | P1 |
| SR7 | SG2, SG9 | T4 | A1, A4, A5 | Inacceptable (documented) | P1 |
| SR8 | SG4, SG5 | T6 | A4, A6 | Undesirable → Tolerable | P1 |
| SR9 | SG3 | T7 | A2, A3 | Undesirable → Tolerable | P1 |
| SR10 | SG3 | T8 | A1, A2, A3 | Undesirable → Tolerable | P1 |
| SR13 | SG4, SG7 | T10 | A4, A6 | Inacceptable → Undesirable (residual) | P1 |
| SR14 | SG4 | T10 | A4 | Inacceptable residual → Undesirable | P2 |
| SR15 | SG8 | T12 | A7 | Undesirable → Tolerable | P2 |
| SR16 | SG6, SG9 | T13 | A6 | Undesirable (documented) | P2 |
| SR17 | SG9 | T14 | A1, A2, A8 | Tolerable (monitored) | P2 |
| SR19 | SG3, SG6 | T15 | A1, A2 | Undesirable | P1 (when in use) |
| SR20 | SG8 | T16 | A1 (Av) | Undesirable → Tolerable | P1 (when in use) |
| SR21 | SG2, SG6 | T18 | A9, A10 | Undesirable (bounded) | P1 (when in use) |
| SR22 | SG6, SG9 | T17, T18 | A9, A10 | forward-compat hatch | P3 |
| SR23 | SG4, SG7, SG8 | T19 | A9 (Av) | Tolerable | P1 (when in use) |
| SR24 | SG6 | T17, T18 | A9, A10 | Locks "non-users retain v0.3.0" | P1 (when in use) |
| SR25 | SG6, SG7 | T18 | A9, A10 | Caps blast radius | P1 (when in use) |
| SR26 | SG9 | T17, T18 | A10 | Rotation runbook | P1 (when in use) |
| SR27 | SG4, SG9 | T20 | A1 | Inacceptable (documented + generator scaffold) | P1 (when in use) |
| SR28 | SG1, SG2, SG6 | T22 | A5 (I) | Tolerable | P1 |
| SR29 | SG3 | T21 | A1, A2 (transient) | Undesirable → Tolerable | P1 (when variants in use) |
| SR30 | SG3, SG9 | T24 | A11 | Undesirable (documented) | P1 |
| SR31 | SG1, SG4, SG7 | T9 | A1, A5 | Inacceptable → Undesirable (documented) | P1 |
| SR32 | SG1, SG4, SG7 | T9 | A1, A5 | Inacceptable → Undesirable (with documented `AshStorage.Plug.Proxy` config) | P1 |
| SR33 | SG2, SG8, SG9 | T23 | A5, A11 | Tolerable (documented) | P2 |
| SR34 | SG4, SG5, SG6 | T25 | A4, A6 | Undesirable → Tolerable (test-locked) | P1 |
| SR35 | SG3, SG9 | T26 | A8 | Tolerable (architectural constraint) | P2 |
| EA1 | SG4, SG7 | T10 | A1, A4 | enabler | P1 |
| EA2 | SG3, SG7 | T2, T3 | A3 | enabler (**load-bearing**) | P1 |
| EA3 | SG4 | T10, T20 | A4, A6 | enabler | P1 |
| EA4 | SG1 | (MC1) | A1, A5 | enabler | P1 |
| EA5 | SG3 | T11 | A2, A3 | enabler | P1 |
| EA6 | SG3 | T7 | A2 | enabler | P1 |
| EA8 | SG9 | T2, T14 | A1, A2 | enabler | P1 |
| EA9 | SG3, SG7 | T15 | A1, A2 | enabler (**load-bearing when in use**) | P1 (when in use) |
| EA10 | SG1, SG3, SG7 | T17, T18 | A9, A10 | enabler (**load-bearing when in use**) | P1 (when in use) |
| EA11 | SG1, SG3 | T24, T4 (when writable) | A11, A1, A5 | enabler (**load-bearing for T24, and for T4 when writable**) | P1 |
