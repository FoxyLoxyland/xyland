---
name: misconfig-audit
description: "Audit konfigurasi Level 0: header, cookie flags, TLS dasar, listing direktori, pesan error verbose"
triggers: { phase: scanning }
safety_level: 0
context_cost: 1000
---
# Skill: Misconfiguration Audit (pasif/ringan)
Cek deterministik tanpa payload: header keamanan (CSP, X-Content-Type-Options, frame protection), flag cookie sesi (Secure/HttpOnly/SameSite), directory listing, halaman error yang membocorkan stack trace/versi, dan endpoint status/debug publik.
## Aturan Nilai
Finding konfigurasi dilaporkan apa adanya dengan dampak jujur — header hilang pada aset tanpa data sensitif adalah *low/informational*, dilarang menaikkan severity demi terlihat banyak finding (itu pola AI slop yang dibenci program). Kelompokkan per host agar laporan tidak banjir duplikat.
