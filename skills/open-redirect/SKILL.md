---
name: open-redirect
description: "Validasi open redirect ke domain marker milik sendiri + kontrol redirect internal"
triggers: { fingerprint: ["redirect-parameter"], phase: validation }
safety_level: 1
context_cost: 1100
validation_rule: knowledge/validation/open-redirect.yaml
---
# Skill: Open Redirect
TP hanya bila browser/client mengikuti redirect ke domain marker milik sendiri dari parameter tsb. Kontrol: nilai redirect internal yang sah harus tetap bekerja normal (membuktikan parameter memang pengendali redirect, bukan kebetulan). Varian yang wajib dicek untuk FN: skema relatif `//marker`, backslash, dan parameter duplikat. Catat apakah redirect butuh interaksi user (klik) — itu memengaruhi severity, bukan validitas.
