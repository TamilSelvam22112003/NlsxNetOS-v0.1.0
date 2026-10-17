# Open Questions

## OQ-5A-001 — Ubuntu 24.04 enrollment failure's original exception (UNCONFIRMED)

**Status:** Unconfirmed historical root cause; do not treat the proposed explanation as proven.

The original Ubuntu 24.04 enrollment failure did not retain a complete traceback in the available CI evidence. The current source includes a UTC-aware certificate-validity compatibility correction in NlsxNetOS commit `ee4b734`, but without the original exception and failing input it is not possible to prove that this was the exact exception raised in the historical enrollment attempt.

**Evidence available as of 2026-10-17:**
- NlsxNetOS stabilization/profile head before the performance work: `6fe02238b10da005717abb68e5df3c17be9c9abe`.
- Router-CA branch `feat/nls-v1` head: `dbcadb92941b64125813b2955652f42ec7e3aff7`.
- Router-CA CI run `39013789493` completed successfully on that head. Both `test` and `cross-repo-control-integration` jobs passed on Ubuntu 22.04 and 24.04.
- Producer-side Ed25519 directory-key encoding correction is in Router-CA commits `eefb10431eee0b509d640a4f75d9debea749bcc2` and `79b66b26d365b400d0963a873768a752970715b1`. This is a separately identified key-encoding issue and should not be conflated with the unconfirmed enrollment exception.

**Closure condition:** capture a complete traceback and sanitized failing field/exception metadata if the enrollment failure recurs on Ubuntu 24.04, or add a deterministic regression test that reproduces the specific original exception. Until then, keep this question marked UNCONFIRMED.
