---
name: api-discovery
description: "Penemuan permukaan API: dokumentasi terekspos, GraphQL introspection, versi & endpoint tak terdokumentasi"
triggers: { phase: enumeration, fingerprint: ["api-host", "graphql", "openapi"] }
safety_level: 0
context_cost: 1500
---
# Skill: API Discovery
## Langkah
1. Cari dokumentasi: `/swagger`, `/openapi.json`, `/api-docs`, `/.well-known/`, Postman collection publik yang tertaut dari JS.
2. GraphQL: cek introspection aktif & endpoint alternatif (`/graphql`, `/api/graphql`, varian versi) — introspection aktif dicatat sebagai konfigurasi, eskalasi dampak lewat skill kelas terkait (idor-auth untuk BOLA).
3. Petakan versi API (v1/v2) — versi lama yang tertinggal adalah sumber FN klasik: tes keamanan sering hanya jalan di versi terbaru.
## Keluaran
Peta endpoint terstruktur ke state (method, auth?, parameter, versi) — bukan daftar URL mentah. Peta inilah input hipotesis agent.
## Jebakan
Dokumentasi publik yang memang sengaja dibuka developer (nilai sebagai informational kecuali membocorkan skema data sensitif/endpoint internal).
