---
name: xss-dom
description: "Analisis DOM XSS: lacak source→sink di JavaScript halaman dengan executor browser"
triggers: { fingerprint: ["spa", "js-heavy", "hash-or-query-driven-ui"], phase: validation }
safety_level: 1
context_cost: 2100
validation_rule: knowledge/validation/xss-dom.yaml
---
# Skill: DOM XSS
## Langkah
1. Dari file JS & HTML, daftar source (`location`, `document.URL`, `postMessage`, storage) dan sink (`innerHTML`, `document.write`, `insertAdjacentHTML`, eval-family).
2. Hanya pasangan source→sink yang alur datanya bisa ditunjukkan yang dites aktif — bukan menembak semua parameter.
3. Executor browser: muat URL dengan nilai marker di source; TP = marker mencapai sink & tereksekusi (bukti DOM/console), kontrol = nilai benign tidak menghasilkan eksekusi.
## Jebakan FP
Sink yang menerima data tapi melalui sanitizer (DOMPurify dsb); source yang tidak bisa dikendalikan penyerang (butuh interaksi lokal).
## Catatan
Hasil analisis statis JS disimpan sebagai artifact; ke konteks hanya pasangan kandidat (P-2/P-6: analisis JS lebar = tugas sub-agent).
