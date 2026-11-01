---
name: path-traversal
description: "Validasi path traversal/LFI dengan berkas penanda yang tidak sensitif"
triggers: { fingerprint: ["file-path-parameter", "download-or-include-feature"], phase: validation }
safety_level: 1
context_cost: 1500
validation_rule: knowledge/validation/path-traversal.yaml
---
# Skill: Path Traversal / LFI
## Langkah
1. Buktikan traversal memakai berkas yang **tidak sensitif dan universal**: mis. membaca penanda yang memang bisa diprediksi isinya untuk verifikasi (atau berkas yang kita tanam sendiri bila fitur memungkinkan), bukan langsung file kredensial.
2. Varian encoding & pemisah path dicatat sebagai matriks (bahan FN check) — satu varian gagal bukan berarti bersih.
3. Kontrol negatif: path di dalam direktori yang sah harus bekerja normal; path traversal harus menghasilkan isi dari **luar** direktori itu agar dihitung TP.
## Batasan
Dilarang membaca & menyimpan berkas kredensial/rahasia nyata sebagai bukti; cuplikan teredaksi secukupnya untuk membuktikan kelas file-nya saja (SR-04).
## Jebakan FP
Respons error server yang memuat string path (itu disclosure path, kelas berbeda); halaman fallback aplikasi yang terlihat seperti isi file.
