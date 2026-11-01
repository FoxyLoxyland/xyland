---
name: wordpress-check
description: "Audit WordPress: versi core/plugin/tema terverifikasi, user enum, REST API & xmlrpc exposure"
triggers: { fingerprint: ["wordpress"], phase: scanning }
safety_level: 0
context_cost: 1600
---
# Skill: WordPress Check
## Langkah
1. Identifikasi versi **dari banyak sinyal** (meta, readme, hash aset, REST API index) dan beri tingkat keyakinan — versi dari satu banner saja tidak cukup untuk klaim CVE (jebakan FP fingerprint-only).
2. Inventaris plugin/tema dari aset yang termuat & endpoint publik; cocokkan ke kartu CVE hanya bila versi terverifikasi.
3. Paparan umum: enumerasi user via REST/`?author=`, xmlrpc aktif, file `wp-config` backup, listing `wp-content/uploads`.
## Aturan
Tidak ada brute-force login. Temuan plugin versi rentan dilaporkan sebagai "versi rentan terverifikasi" sampai ada validasi kelas terkait yang lolos verdict engine.
