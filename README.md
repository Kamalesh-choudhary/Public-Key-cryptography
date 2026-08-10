# Cryptographic Key Management System using PKI

A web-based Public Key Infrastructure (PKI) system built with Python (Flask) and SQLite.

---

**Live Demo:** https://public-key-cryptography.onrender.com
*(Free-tier hosting — may take 30–50s to wake up if idle)*

## Features

- **Key Generation** — RSA-2048, RSA-4096, ECC P-256 / P-384 / P-521
- **Certificate Authority (CA)** — Initialize a Root CA, issue & revoke X.509 v3 certificates
- **Document Signing** — Sign documents using RSA-PKCS1v15 or ECDSA with SHA-256
- **Signature Verification** — Verify document integrity and detect tampering
- **Web Dashboard** — Full dark-themed GUI with real-time stats

---

## Project Structure

```
pki_system/
├── app.py                  # Flask entry point
├── database.py             # SQLite schema & DB helpers
├── requirements.txt        # Python dependencies
├── routes/
│   ├── keys.py             # Key generation & management API
│   ├── ca.py               # Certificate Authority API
│   ├── signing.py          # Document signing & verification API
│   └── dashboard.py        # Dashboard stats API
├── templates/
│   ├── base.html           # Base layout template
│   ├── index.html          # Dashboard page
│   ├── keys.html           # Key management page
│   ├── ca.html             # Certificate Authority page
│   └── signing.html        # Document signing page
└── static/
    └── css/
        └── main.css        # Stylesheet
```

---

## Setup & Run

### Prerequisites
- Python 3.8 or above

### Step 1 — Install dependencies
```bash
pip install flask cryptography
```

### Step 2 — Run the application
```bash
cd pki_system
python app.py
```

### Step 3 — Open in browser
```
http://localhost:5000
```

---

## How to Use

### 1. Generate Keys
- Go to **Key Management**
- Choose RSA (2048 or 4096-bit) or ECC (P-256, P-384, P-521)
- Give the key a name and click **Generate Key Pair**

### 2. Setup Root CA
- Go to **Certificate Authority → Root CA Setup**
- Select a key pair, fill in CN / Org / Country
- Click **Initialize Root CA**

### 3. Issue Certificates
- Go to **Certificate Authority → Issue Certificate**
- Select a subject key, fill in details, click **Sign & Issue Certificate**

### 4. Sign a Document
- Go to **Document Signing → Sign Document**
- Paste document content, select a signing key, click **Sign Document**
- Copy the generated Base64 signature

### 5. Verify a Signature
- Go to **Document Signing → Verify Signature**
- Paste the original content + signature + select the key
- Click **Verify Signature** to confirm authenticity

---

## Algorithms Used

| Algorithm | Usage |
|-----------|-------|
| RSA-2048 / RSA-4096 | Key generation, digital signing (PKCS1v15) |
| ECC P-256 / P-384 / P-521 | Key generation, digital signing (ECDSA) |
| SHA-256 | Document hashing |
| X.509 v3 | Certificate format standard |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3, Flask |
| Cryptography | `cryptography` library (PyCA) |
| Database | SQLite (via `sqlite3`) |
| Frontend | HTML5, CSS3, Vanilla JavaScript |
| Fonts | Google Fonts (Rajdhani, Exo 2, Share Tech Mono) |
