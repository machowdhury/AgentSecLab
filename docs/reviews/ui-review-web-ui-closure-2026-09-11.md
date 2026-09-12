# UI review — Phase 2C.4 evidence closure

**Date:** 2026-09-11  
**Pass:** closure (does not replace pass-1 reports)  
**Surfaces:** AcmeBank COMPLETED / ERROR; Attack DENIED; responsive READY  
**Screenshots:**  
- `docs/screenshots/acmebank/pass2_completed.png`  
- `docs/screenshots/acmebank/pass2_error.png`  
- `docs/screenshots/attack-ui/pass2_denied.png`  
- `docs/screenshots/acmebank/pass2_ready_390.png` (representative mobile)

Canonical tokens: `docs/AGENTSEC_DESIGN_SYSTEM.md`. Pass-1 reports unchanged.

---

## Roles (short)

SOC: COMPLETED and DENIED both show a copyable `run.id`.  
Instructor: COMPLETED copy says governed calls **started**, not that a loan was approved; ERROR says `llm_invocation` is not DENY; Attack DENIED does not claim the injection succeeded.  
UX: READY→RUNNING→COMPLETED observed on live host Ollama. Duplicate status sentence remains.  
A11y: keyboard check MEASURED separately (`docs/screenshots/web-ui-keyboard-validation.json`).

---

## BLOCKER / HIGH

None remaining on these screenshots.

---

## Residual MEDIUM / LOW (unchanged scope; not fixed this pass)

**MEDIUM — duplicated status sentence on AcmeBank** (`pass2_completed.png`, `pass2_error.png`). Live region and `#result-summary` repeat the same paragraph. Trivial fix if wanted: keep the live line and hide the summary when it would duplicate. Semantics unchanged.

**MEDIUM — Attack mesh URL** (`pass2_denied.png`). `http://acmebank:5000` is what the Attack container posts to. Trivial copy-only fix if wanted: also print the host URL `http://127.0.0.1:5000` as “browser address.” Do not fake a different target.

**LOW — header wrap / lab profile in chrome / 390px textarea clip** as in pass-1/pass-2 reviews.

No silent changes applied.
