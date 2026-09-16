# HWSEC Manual Verdict Interpretation Guide

This guide explains how to interpret analysis verdicts and Proof-of-Vulnerability (PoV) statuses output by `hwsec console`.

## Core Verdict Definitions

| Verdict | Meaning | Requirement |
|:---|:---|:---|
| **`DETECTED`** | Ground truth vulnerability confirmed. Static analysis hypothesis was validated by a runtime execution witness and causal control test. | PoV bundle generated and verified. |
| **`NOT_DETECTED`** | Target is safe or fix has successfully mitigated the vulnerability. Runtime witness or negative control confirmed safe behavior. | No exploit state achieved. |
| **`INCONCLUSIVE`** | Analysis could not conclusively prove or disprove flaw (e.g. required execution tool missing, or sandbox timeout). | Requires additional toolchain setup or manual triage. |

## Proof-of-Vulnerability (PoV) Statuses

| PoV Status | Meaning |
|:---|:---|
| **`PoV VERIFIED`** | Independent sandbox replay executed the synthesized PoV bundle and reproduced the security assertion breach. |
| **`PoV UNVERIFIED`** | PoV script was generated but execution failed to reproduce the exploit in the local sandbox environment. |
| **`POV_BLOCKED_BY_FIX`** | Replay against the fixed target was rejected safely because input validation or boundary checks prevented payload execution. |

## Ground Truth Verdicts Reference Matrix

See [`verdicts.json`](file:///e:/Intern/hwsec/manual_tests/expected/interpretation/verdicts.json) for the complete list of target cases and expected engine verdicts.
