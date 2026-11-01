# 10 — PoC Script & Validation Rules per Finding

> **Fitur inti (pembeda utama / validation-first).** Setiap finding tidak berhenti di "nuclei bilang ini vuln". Setiap finding wajib punya: **(1) Validation Rule** yang bisa diuji mesin secara deterministic, **(2) PoC Script** yang bisa dijalankan ulang manusia maupun mesin, dan **(3) Verdict** True Positive / False Positive / False Negative / Inconclusive berbasis bukti — bukan opini AI.

Ditambahkan atas masukan Ucup, 1 Nov 2026.

## 1. Konsep: 3 Artefak per Finding

```
results/<job-id>/findings/<finding-id>/
├── finding.json          # data finding terstruktur
├── validation.yaml       # (1) Validation Rule — deklaratif, deterministic
├── poc.py                # (2) PoC Script — executable, aman, standalone
│                         #     alternatif format: poc.sh (curl) / poc.go
├── verdict.json          # (3) Hasil validasi mesin (lihat §4)
└── evidence/
    ├── request.txt
    ├── response.txt      # diredaksi
    └── baseline.txt      # response kontrol negatif / baseline
```

Prinsip desain mengikuti Shannon: **"No exploit, no report"** — finding yang PoC-nya tidak terkonfirmasi tidak boleh naik status jadi laporan final; status maksimalnya `needs-manual-check`.

## 2. Validation Rule (`validation.yaml`)

Format deklaratif, terinspirasi matcher/extractor Nuclei tapi diperluas dengan **kontrol negatif dan baseline** — dua hal yang membedakan TP asli dari FP.

```yaml
id: VAL-XSS-REFLECTED-001
finding_ref: "<finding-id>"
vuln_class: xss-reflected
safety_level: 1            # 0=safe, 1=safe-active, 2=intrusive, 3=manual-only (§5)

positive_test:
  request:
    method: GET
    url: "{{target}}/search?q={{payload}}"
    payload: 'xyland<svg/onload=1>'   # payload unik & non-destruktif, ada marker khas kita
  matchers:                # SEMUA harus terpenuhi
    - type: word
      location: body
      words: ["xyland<svg/onload=1>"]
      condition: present-unencoded   # terpantul TANPA encoding = rentan
    - type: status
      status: [200]

negative_control:          # WAJIB ada — inilah anti-FP-nya
  request:
    method: GET
    url: "{{target}}/search?q=xyland-benign-marker"
  matchers:
    - type: word
      location: body
      words: ["xyland-benign-marker"]
      expect_reflection_context: different

baseline:
  description: "Request normal tanpa payload untuk pembanding response"

reproducibility:
  runs_required: 2         # PoC harus berhasil 2x berturut-turut untuk 'confirmed'
  allow_flaky: false

verdict_logic:
  true_positive: "positive matches AND negative control differs AND reproducible"
  false_positive: "positive fails on re-run OR control shows same behaviour"
  inconclusive: "timeout / WAF / rate-limit / response tidak stabil"
```

### Kenapa kontrol negatif & baseline itu wajib?
Sebagian besar false positive lahir karena tidak ada pembanding:
- Halaman yang memantulkan *semua* input (termasuk yang sudah di-encode aman) akan terlihat "XSS" oleh matcher sederhana.
- Endpoint yang selalu balas `200` + halaman error generik akan terlihat "rentan" untuk banyak template.
- File `/.git/config` yang dibalas halaman custom-404 berisi kata "repository" akan terlihat seperti exposure.
→ Rule kita selalu membandingkan: **respons payload vs respons benign vs respons baseline**. Beda yang *spesifik terhadap payload* = sinyal asli.

## 3. PoC Script (`poc.py` / `poc.sh`)

### Aturan format script
| Aspek | Aturan |
|---|---|
| Bahasa default | Python 3 (`requests` saja, tanpa dependensi aneh) — paling mudah dibaca triager & hunter. Opsi ekspor: Bash+`curl` (paling transparan) dan Go (standalone binary) |
| Standalone | Satu file, target & parameter di bagian atas, bisa jalan tanpa tool kita: `python3 poc.py https://target/...` |
| Self-verifying | Script **mencetak verdict sendiri** & exit code standar (lihat di bawah), bukan cuma mencetak response mentah untuk ditebak manusia |
| Aman by construction | Payload dari katalog aman (§5). Tidak ada payload destruktif di template mana pun. |
| Redaksi | Token/cookie/data pribadi di output otomatis diredaksi |
| Batas | Timeout keras, maks. request dibatasi (default ≤ 10), rate-limit bawaan |
| Header wajib | Komentar di kepala file: finding ID, vuln class, target, tanggal, catatan "hanya untuk target berizin / in-scope" |

### Kontrak output script
```bash
$ python3 poc.py https://example.com/search
[+] Positive test : MATCH (payload reflected unencoded)
[+] Negative ctrl : OK (benign marker handled differently)
[+] Re-run        : MATCH (2/2)
VERDICT: CONFIRMED_TRUE_POSITIVE
# exit code: 0 = confirmed TP | 2 = false positive | 3 = inconclusive | 4 = blocked by safety/scope
```

### Siapa yang membuat script?
1. **Template katalog dulu (deterministic):** untuk kelas vuln umum, script di-generate dari template per kelas yang sudah di-review manusia (§6) — AI hanya mengisi parameter (URL, nama parameter, payload marker, bukti awal).
2. **AI drafting (terbatas):** untuk finding aneh di luar katalog, AI boleh *menulis draft* script — tapi script itu berstatus `unreviewed`, **tidak boleh dieksekusi otomatis**, hanya bisa dijalankan setelah user membaca & menyetujui isinya (human-in-the-loop).
3. AI tidak pernah boleh memperluas payload menjadi lebih agresif dari katalog.

## 4. Verdict Engine — TP / FP / FN / Inconclusive

### 4a. Klasifikasi per finding (yang sudah ditemukan scanner)
| Verdict | Syarat bukti (semua diperiksa mesin dari `validation.yaml`) |
|---|---|
| `confirmed` (True Positive) | Positive matcher terpenuhi + kontrol negatif berbeda + reproduksi 2/2 run |
| `likely` | Positive terpenuhi 1/2 run, atau kontrol negatif lemah/tidak lengkap |
| `false-positive` | Positive gagal saat re-run, **atau** kontrol negatif menunjukkan perilaku yang sama, **atau** baseline = respons payload (generik) |
| `inconclusive` | WAF memblokir, timeout, rate-limited, atau respons tidak stabil antar run |

Hanya `confirmed` dan `likely` (dengan catatan) yang diteruskan ke fase Reporting. `false-positive` tetap disimpan (tidak dihapus) untuk audit & bahan evaluasi akurasi scanner.

### 4b. Cek False Negative — yang *terlewat* scanner
FN tidak bisa dicek dari finding yang ada, jadi engine punya jalur terpisah — **coverage & variant check**:

| Teknik FN | Cara Kerja |
|---|---|
| **Variant matrix** | Untuk tiap endpoint+parameter yang *sudah ditemukan* tapi dinyatakan bersih, jalankan varian aman: encoding ganda, perubahan case, method lain (GET↔POST), header tambahan, trailing slash/`;`, parameter duplikat. Nuclei standar sering berhenti di 1 varian. |
| **Auth differential** | Tes ulang endpoint yang sama dalam 3 state: tanpa auth, user A, user B. Selisih respons antar state = kandidat IDOR/auth issue yang sering lolos dari scan unauth saja. |
| **Coverage gap report** | Setiap run menghasilkan daftar: endpoint/parameter yang ditemukan crawler tapi **tidak pernah dites** oleh template mana pun → ini daftar "potensi FN" yang eksplisit, ditampilkan ke user, bukan disembunyikan. |
| **Template gap** | Bandingkan tech stack hasil fingerprint vs set template yang benar-benar jalan. Jika tech terdeteksi tapi templatenya tidak ada/tidak jalan → tandai sebagai risiko FN. |

Hasil jalur FN bukan finding otomatis — hasilnya adalah **kandidat baru** yang masuk kembali ke Fase Validasi yang sama (positive + control + reproducibility). Siklusnya tertutup: tidak ada kandidat yang jadi laporan tanpa lolos verdict engine.

## 5. Safety Rules untuk Semua PoC (Rules of Engagement)

| ID | Rule |
|---|---|
| SR-01 | **Scope only** — script & rule menolak jalan untuk host di luar scope job, diperiksa sebelum request pertama |
| SR-02 | **Read-only default** — Level 0–1 hanya membaca. Tidak ada pembuatan/pengubahan/penghapusan data |
| SR-03 | **Tanpa payload destruktif** — dilarang di semua level otomatis: `DROP/DELETE`, penghapusan file, perubahan password, spam, mass-exfiltration |
| SR-04 | **Bukti secukupnya** — untuk IDOR/data exposure, bukti dibatasi maks. 1–2 record sampel, diredaksi. Cukup membuktikan, tidak menguras data |
| SR-05 | **Tanpa DoS & brute-force** — tidak ada PoC otomatis untuk DoS, credential stuffing, atau rate-limit exhaustion |
| SR-06 | **Human approval untuk Level 2** — aksi intrusif (mis. upload test file, membuat akun/objek uji) wajib persetujuan user per eksekusi, dan wajib ada langkah cleanup |
| SR-07 | **Level 3 = manual only** — kelas seperti RCE command execution penuh, SQLi data dumping: tool hanya menghasilkan *instruksi & script untuk dibaca*, tidak ada eksekusi otomatis sama sekali |
| SR-08 | **Stop condition** — script berhenti sendiri jika: target mengembalikan error beruntun, terdeteksi WAF block, atau respons menunjukkan dampak di luar dugaan |
| SR-09 | **Audit log** — setiap eksekusi PoC (oleh user maupun engine) tercatat: waktu, finding, level, hasil, siapa yang menyetujui |
| SR-10 | **Jujur soal ketidakpastian** — jika verdict `inconclusive`, tampilkan apa adanya. Dilarang menaikkan status karena "kemungkinan besar rentan" |

### Level per kelas vuln (draft katalog)
| Level | Contoh kelas | Eksekusi |
|---|---|---|
| 0 — Safe | Security header hilang, cookie flag, version disclosure, CORS refleksi sederhana | Otomatis |
| 1 — Safe-active | Reflected XSS (payload marker), open redirect, exposed file check, IDOR read (sampel terbatas, antar akun milik sendiri) | Otomatis dalam mode `standard` |
| 2 — Intrusive | Stored XSS (objek uji sendiri), file upload test, SSRF ke server interaksi kita sendiri (interactsh) | **Persetujuan user per eksekusi** |
| 3 — Manual only | SQLi extraction, RCE, auth bypass yang mengubah state akun orang lain | Instruksi + script untuk review manual, **tidak dieksekusi tool** |

## 6. Katalog Rule Awal (prioritas bangun)
Urutan berdasarkan frekuensi di bug bounty & kemudahan validasi deterministic:

1. Exposed files & misconfig (`.git`, `.env`, backup, debug endpoint) — matcher + baseline 404 check
2. Reflected XSS — reflection unencoded + kontrol benign
3. Open redirect — redirect ke domain marker kita + kontrol redirect internal normal
4. IDOR (read) — auth differential A/B/tanpa-auth, sampel terbatas
5. CORS misconfig — refleksi Origin + kontrol Origin acak
6. SSRF (blind) — korelasi interactsh + kontrol tanpa parameter
7. SQLi (error/time-based *ringan*) — error signature + kontrol; time-based hanya Level 2 dengan delay kecil & batas ketat

Setiap entri katalog = 1 file `validation` template + 1 generator PoC + unit test terhadap target lab rentan & target lab aman (untuk memastikan katalog sendiri tidak menghasilkan FP).

## 7. Peran AI di Fitur Ini (tetap dibatasi)
- ✅ Memilih rule katalog yang cocok untuk sebuah finding
- ✅ Mengisi parameter rule/script dari bukti finding (URL, parameter, marker)
- ✅ Menjelaskan verdict dalam bahasa manusia di laporan ("kenapa ini TP, kenapa itu FP")
- ✅ Mengusulkan varian FN-check baru — usulannya masuk antrean review, bukan langsung jalan
- ❌ Menulis payload di luar katalog untuk eksekusi otomatis
- ❌ Mengubah verdict mesin — verdict ditentukan rule deterministic; AI hanya boleh memberi catatan
- ❌ Menjalankan script Level 2–3 tanpa persetujuan user yang tercatat
