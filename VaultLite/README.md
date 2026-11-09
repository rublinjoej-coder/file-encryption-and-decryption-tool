# 🛡️ VaultLite – Secure File Encryption & Decryption Tool

[![Standard](https://img.shields.io/badge/Security-AES--256--GCM-7c3aed?style=for-the-badge&logo=shield)](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt)
[![Key Derivation](https://img.shields.io/badge/KDF-PBKDF2--SHA256-3b82f6?style=for-the-badge)](https://en.wikipedia.org/wiki/PBKDF2)
[![Platform](https://img.shields.io/badge/Architecture-100%25%20Client--Side-10b981?style=for-the-badge)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Pure%20Vanilla)-06b6d4?style=for-the-badge)](https://github.com/)

A modern, high-performance, client-side cybersecurity web application designed to protect sensitive files with authenticated encryption directly inside your web browser. 

**VaultLite** uses the browser's hardware-accelerated **Web Crypto API** to perform **AES-256-GCM** encryption and **PBKDF2-HMAC-SHA256** key derivation. No files or passphrases ever leave your device.

---

## 1. Project Overview

In an era of centralized cloud vulnerabilities and data breaches, **VaultLite** serves as a lightweight, zero-knowledge privacy vault. Whether you are encrypting financial records, private source code, identity documents, or personal photos, VaultLite converts your files into tamper-evident binary `.sfe` (Secure File Encryption) containers that can only be unlocked with your master passphrase.

### Core Value Proposition
- **Zero Server Uploads**: Operates 100% offline in memory. No server, no telemetry, no tracking.
- **Authenticated Encryption**: Employs AES-GCM to guarantee both confidentiality and cryptographic integrity.
- **Hardware Accelerated**: Leverages the browser's native `window.crypto.subtle` engine for C++-level performance.
- **True Portability**: Single client package running on modern desktop and mobile browsers.

---

## 2. Project Objectives

- **Practical Skill Development**: Learn and apply cryptography best practices in JavaScript and modern web standards.
- **Standardized Cryptography**: Implement NIST-approved encryption primitives (AES-256-GCM, PBKDF2) rather than home-brewed ciphers.
- **Anti-Tampering Integrity**: Detect corruption, accidental bit flips, and malicious tampering using GCM authentication tags.
- **User-Centric Security UX**: Demystify cryptography with password strength feedback, clear error reporting, and visual progress indicators.

---

## 3. Technologies Used

| Technology | Purpose |
| :--- | :--- |
| **HTML5** | Semantic, accessible layout and drag-and-drop file interface. |
| **CSS3** | Dark navy cybersecurity design, glowing accents, flexbox/grid, responsive layouts. |
| **Vanilla JavaScript (ES6+)** | Lightweight application logic without external framework overhead. |
| **Web Crypto API (`crypto.subtle`)** | Hardware-accelerated, timing-attack-resistant cryptographic primitives. |
| **CSPRNG (`crypto.getRandomValues`)** | Cryptographically secure pseudo-random number generation for salts and IVs. |
| **File API & Blob API** | Direct in-memory file reading, binary packaging, and local client downloads. |

> 🚫 **Zero External Libraries**: No React, Vue, Angular, jQuery, Node.js backend, Python, PHP, or cloud database dependencies.

---

## 4. Key Features

### 🔒 File Encryption
1. **Drag & Drop Upload**: Seamlessly drop files of any type (PDF, PNG, MP4, ZIP, TXT, etc.).
2. **File Metadata Preview**: Displays real-time file name, formatted byte size, and MIME category.
3. **Master Passphrase with Confirmation**: Live validation ensures passwords match before processing.
4. **Real-Time Password Strength Meter**: Evaluates length, uppercase, lowercase, numbers, and symbols with dynamic visual feedback.
5. **Show/Hide Passphrase Toggle**: User-friendly eye icon toggle for visibility.
6. **Cryptographic Random Salt & IV**: Generates a 16-byte salt and 12-byte IV per encryption operation.
7. **Hardened PBKDF2 Key Derivation**: 300,000 rounds of HMAC-SHA-256 to mitigate brute-force attacks.
8. **AES-256-GCM Authenticated Encryption**: Protects data privacy and generates a 128-bit authentication tag.
9. **Structured `.sfe` Binary Container**: Custom binary format encapsulating metadata, salt, IV, and ciphertext.
10. **Instant Local Download**: Browser download triggered automatically with one-click manual fallback.

### 🔓 File Decryption
1. **Container Validation**: Validates the `.sfe` magic identifier (`VLTE`) and container version (`0x01`).
2. **Passphrase Prompt**: User supplies the secret passphrase used during encryption.
3. **Dynamic Key Re-derivation**: Derives the exact key using the file's embedded salt and iteration count.
4. **GCM Authentication Tag Check**: Decrypts and verifies the 128-bit integrity tag.
5. **Tamper & Wrong Password Detection**: Returns immediate, clean errors if the passphrase is incorrect or any byte was altered.
6. **Fidelity Restoration**: Restores the original filename, file type, and exact binary payload.

### 🎨 User Interface & Security Dashboard
- **Dark Navy Theme**: Modern command-center aesthetic (`#070b14`, `#0e1526`).
- **Cyber Accents**: Purple and blue glowing gradients (`#8b5cf6`, `#3b82f6`, `#06b6d4`).
- **Responsive Design**: Flawlessly adapts from 320px mobile screens to 4K ultra-wide monitors.
- **Toast Notification System**: Instant status updates (Success, Error, Warning, Info).
- **Technical Specs Table**: One-click "Copy Specs" button for security audits and technical documentation.
- **Educational Explanations**: First-time user guide and honest cybersecurity disclaimer.

---

## 5. Encryption Algorithm & File Format

### Cryptographic Pipeline

```
[Plaintext File] ──┐
                   ▼
  Passphrase ──► [PBKDF2-HMAC-SHA256] ──► [256-bit AES Key]
                   ▲ (300,000 Rounds)           │
       Salt  ──────┘ (16 Random Bytes)          │
                                                ▼
  12-byte Random IV ───────────────────► [AES-256-GCM Cipher]
                                                │
                                                ▼
                                    [Ciphertext + 128-bit Auth Tag]
```

### The `.sfe` Binary Format Specification

VaultLite encodes the encrypted package into a compact, self-contained binary layout:

| Offset / Field | Byte Length | Description |
| :--- | :---: | :--- |
| `0x00 - 0x03` | 4 bytes | Magic Header: ASCII `VLTE` (`0x56, 0x4C, 0x54, 0x45`) |
| `0x04` | 1 byte | Format Version: `0x01` |
| `0x05 - 0x08` | 4 bytes | PBKDF2 Iteration Count (Uint32 Big-Endian: e.g. `300,000`) |
| `0x09` | 1 byte | Salt Byte Length (Uint8: `16`) |
| `0x0A - 0x19` | 16 bytes | Cryptographic Random Salt |
| `0x1A` | 1 byte | IV Byte Length (Uint8: `12`) |
| `0x1B - 0x26` | 12 bytes | AES-GCM Initialization Vector |
| `0x27 - 0x28` | 2 bytes | Filename Byte Length $N$ (Uint16 Big-Endian) |
| Variable ($N$) | $N$ bytes | Original Filename (UTF-8 encoded) |
| Next 2 bytes | 2 bytes | MIME Type Byte Length $M$ (Uint16 Big-Endian) |
| Variable ($M$) | $M$ bytes | Original MIME Type (UTF-8 encoded) |
| Remaining | Remainder | AES-256-GCM Ciphertext + 128-bit (16 bytes) Authentication Tag |

---

## 6. Project Structure

```
VaultLite/
│
├── index.html              # Main HTML5 application shell & SVG iconography
│
├── css/
│   └── style.css           # Premium cybersecurity dashboard stylesheet
│
├── js/
│   ├── app.js              # UI controller, drag & drop, strength meter, notifications
│   ├── encryption.js       # Core encryption module (PBKDF2, AES-GCM, binary pack)
│   └── decryption.js       # Core decryption module (binary unpack, AES-GCM verify)
│
├── assets/
│   └── icons/
│       └── favicon.svg     # High-tech cybersecurity shield icon
│
├── README.md               # Comprehensive project documentation
└── .gitignore              # Git ignore rules
```

---

## 7. Installation & Setup Instructions

Because VaultLite is built exclusively with standard web technologies, **no build steps or package managers (`npm install`) are required**.

### Option A: Using Node.js (Recommended - Already on your system)
You have Node.js installed, which includes a zero-dependency server script:
```powershell
node server.js
```
Then open `http://localhost:3000` in your web browser.

### Option B: VS Code Live Server
1. Open the project folder in **Visual Studio Code**.
2. Install the **Live Server** extension (by Ritwick Dey).
3. Right-click `VaultLite/index.html` and select **"Open with Live Server"**.
4. The application will launch at `http://127.0.0.1:5500/`.

### Option C: Python Local Server (If Python is installed)
```bash
python -m http.server 8000
```
Open `http://localhost:8000/`.

### Option C: Direct File Opening
You can double-click `index.html` to open it in your browser. *(Note: While modern Chrome, Edge, and Firefox support Web Crypto on `file:///`, using a localhost server is recommended for strict standards compliance).*

---

## 8. How to Use the Application

### How to Encrypt a File
1. Open VaultLite in your browser. By default, the **"Encrypt File"** tab is active.
2. Drag and drop any file into the upload zone, or click to browse.
3. Review the selected file's name and size in the file badge.
4. Enter a strong master passphrase in the **Master Passphrase** field.
5. Check the **Passphrase Strength Meter** to ensure high entropy.
6. Re-type the exact same passphrase into **Confirm Passphrase**.
7. Click the **Encrypt File** button.
8. The progress bar will indicate key derivation and encryption. Once finished, your browser will automatically download the encrypted `.sfe` file.

### How to Decrypt a File
1. Click the **"Decrypt File (.sfe)"** tab.
2. Drag and drop your `.sfe` encrypted file into the upload zone.
3. Enter the original master passphrase in the passphrase field.
4. Click **Decrypt File**.
5. VaultLite will authenticate the container, verify data integrity, restore the original filename, and initiate the download of your original decrypted file.

---

## 9. Testing & Quality Assurance Checklist

The following 9 core test scenarios have been tested and verified:

| # | Test Scenario | Expected Outcome | Result |
| :-: | :--- | :--- | :-: |
| **1** | Encrypt a plain text (`.txt`) file | Creates valid `.sfe` package with headers, salt, IV, and ciphertext | ✅ Pass |
| **2** | Decrypt `.sfe` file with correct passphrase | Successfully decrypts and initiates download of restored file | ✅ Pass |
| **3** | Byte-for-byte fidelity verification | SHA-256 hash of decrypted file matches original file 100% | ✅ Pass |
| **4** | Decrypt with incorrect password | Web Crypto rejects authentication tag; shows clear error toast | ✅ Pass |
| **5** | Decrypt corrupted / modified `.sfe` file | AES-GCM detects modified byte; throws authentication failure error | ✅ Pass |
| **6** | Test varied file formats (`.png`, `.pdf`, `.zip`, `.mp4`) | All binary structures preserved accurately across types | ✅ Pass |
| **7** | Test empty (0-byte) files | Encrypts and decrypts empty files without crashing or hanging | ✅ Pass |
| **8** | Memory & resource testing | Successfully processes files within browser memory constraints | ✅ Pass |
| **9** | Multi-device responsive layout | Layout adapts cleanly on mobile (320px+), tablet, and desktop | ✅ Pass |

---

## 10. Security Limitations & Transparency

In cybersecurity, transparency is paramount. VaultLite adheres to the principle of honest security disclosure:

1. **Passphrase Dependency**: Cryptographic strength is bounded by the entropy of your passphrase. A weak password (e.g. `123456` or `password`) is vulnerable to offline brute-force attacks even with 300,000 PBKDF2 iterations.
2. **No Password Recovery**: By design, VaultLite has zero backdoors. If you forget your passphrase, **your data is permanently unrecoverable**.
3. **Endpoint Security**: If your host operating system is compromised with malware, keyloggers, or malicious browser extensions, data may be intercepted during user entry in memory.
4. **File Size Limits**: Because files are read into client RAM as ArrayBuffers, extremely large files (e.g., > 1-2 GB) may exceed browser memory allocations depending on available device RAM.

---

## 11. Future Enhancements

- [ ] Chunked streaming encryption via Web Streams API for multi-gigabyte files.
- [ ] Argon2id key derivation option via WebAssembly.
- [ ] Asymmetric public-key encryption (RSA-OAEP or ECDH) for multi-recipient sharing.
- [ ] Steganographic container embedding (hiding `.sfe` packages inside cover images).
- [ ] Multi-file batch encryption and folder archive creation.

---

## 12. Author & Acknowledgments

- **Project**: VaultLite – Secure File Encryption & Decryption Tool
- **Version**: `1.0.0`
- **Domain**: Cybersecurity Skill Development Project
- **Standards Compliant**: NIST SP 800-38D (AES-GCM), RFC 8018 (PBKDF2)
- **License**: MIT License — open for educational and personal use.
