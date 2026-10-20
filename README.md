# MUKU EXPLOITS — CRYPTO LAB

> **Understand the Code. Master the Cipher. Protect the Data.**

An interactive, **educational** cryptography lab that runs 100% in your browser. Encrypt, decrypt, hash, sign and simulate end-to-end encryption using the real **Web Crypto API** — no backend, no API keys, no tracking.

**Hinglish summary:** Ye ek single-page website hai jo browser me hi real cryptography (AES, RSA, SHA, ECDSA) chalakar sikhati hai. Koi server nahi, koi data bahar nahi jaata. Sirf learning ke liye hai, production security ke liye nahi.

---

## Table of contents
1. [Features](#features)
2. [Tech stack](#tech-stack)
3. [Folder structure](#folder-structure)
4. [How to run](#how-to-run)
5. [How each section works](#how-each-section-works)
6. [Package formats](#package-formats)
7. [Security and privacy design](#security-and-privacy-design)
8. [Manual testing checklist](#manual-testing-checklist)
9. [Browser compatibility](#browser-compatibility)
10. [Limitations and caveats](#limitations-and-caveats)
11. [Roadmap](#roadmap)
12. [Disclaimer and license](#disclaimer)

---

## Features

| Section | What you can do |
|---|---|
| Encryption workbench | AES-256-GCM, password-based encryption (PBKDF2), RSA-OAEP; encrypt, decrypt, copy, clear, tamper test |
| Encoding lab | Base64, Hex (UTF-8), URL encode/decode |
| Hashing lab | SHA-256 / 384 / 512, hash compare, avalanche-effect demo |
| E2EE simulator | Alice → Bob hybrid encryption (RSA-OAEP + AES-GCM) in 6 steps |
| Classical ciphers | Caesar, ROT13, Vigenère, XOR, Caesar brute-force |
| Digital signatures | ECDSA P-256 + SHA-256 sign and verify |
| Terminal | Safe simulated console with demo commands |
| Privacy panel | Clear-all button and privacy notes |

## Tech stack
- HTML5, CSS3, vanilla JavaScript (ES6+)
- Web Crypto API (`crypto.subtle`) for all real cryptographic operations
- No frameworks, no npm, no external requests
- A Content-Security-Policy meta tag blocks all outside connections (`connect-src 'none'`)

## Folder structure
```
muku-crypto-lab/
├── index.html   # Page structure, sections, CSP
├── style.css    # Dark cyber theme, responsive layout, reduced-motion support
├── script.js    # All logic: crypto, UI wiring, terminal
└── README.md    # This file
```

## How to run

**Option A — VS Code Live Server (easiest)**
1. Install [VS Code](https://code.visualstudio.com/) and the *Live Server* extension.
2. Open the `muku-crypto-lab` folder (File → Open Folder).
3. Right-click `index.html` → **Open with Live Server**.

**Option B — Python**
```bash
cd muku-crypto-lab
python -m http.server 8000
# open http://localhost:8000
```

**Option C — GitHub Pages**
Push the repo, then Settings → Pages → deploy from the `main` branch. GitHub Pages uses HTTPS, so Web Crypto works.

> **Important:** Web Crypto only works in a *secure context* (`https://` or `localhost`). Opening `index.html` by double-click (`file://`) may fail — use one of the options above.

---

## How each section works

### 1. Encryption workbench
Pick an algorithm, type a message, press **Generate Key** (if needed), then **Encrypt**. The output is a JSON package you can copy.

- **AES-256-GCM** — A random 256-bit key is generated and kept *in memory only* (non-extractable, never displayed). Each encryption uses a fresh random 96-bit IV and a 128-bit authentication tag. The IV is not secret, but must never repeat for the same key.
- **Password mode** — Your password goes through PBKDF2 (SHA-256, 310,000 iterations) with a fresh random 16-byte salt to derive an AES-GCM key. Salt, IV and iteration count are stored in the package. A weak password is still guessable.
- **RSA-OAEP** — A 2048-bit key pair with SHA-256. Max message size is 190 bytes; longer messages are rejected with an explanation. Real systems use hybrid encryption (see E2EE).

**To decrypt:** press **Decrypt**. If the message box contains a JSON package, that is decrypted; otherwise the output box is used. Keys must still be in memory (same page session), and password mode needs the same password.

**Tamper test:** flips one bit of the ciphertext and tries to decrypt. AES-GCM's authentication tag makes this fail — showing integrity protection.

### 2. Encoding lab
Base64, hexadecimal and URL conversion. **Encoding is not encryption** — there is no key and no secrecy; anyone can reverse it. Invalid input shows an error message.

### 3. Hashing lab
Computes SHA-256/384/512 digests locally.
- **Compare** uses a constant-time-style loop (browser timing is still not a side-channel guarantee).
- **Avalanche demo** flips one character and shows how many bits of the digest change (roughly half).
- A hash is one-way. It is *not* encryption, and plain SHA-256 is *not* a good password-storage method (use Argon2id, scrypt or tuned PBKDF2/bcrypt).

### 4. E2EE simulator (Alice and Bob)
Click the buttons in order:
1. **Generate Demo Keys** — RSA-OAEP pairs for Alice and Bob.
2. **Compose Message** — Alice's text is captured.
3. **Encrypt Message** — a random AES-GCM session key encrypts the message; Bob's *public* key wraps that session key.
4. **Send Encrypted Packet** — the "network" only sees ciphertext, IV and the wrapped key.
5. **Decrypt at Receiver** — Bob's *private* key recovers the session key, which decrypts the message.
6. **Reset Simulation** — clears the in-memory state.

This is a learning demo. It has **no** identity verification, replay protection or forward secrecy, and does not protect against a compromised device.

### 5. Classical ciphers
Caesar (shift), ROT13, Vigenère (keyword, letters only) and XOR (hex output). The **Brute-force Caesar** button shows all 25 shifts to prove how weak it is. None of these are secure.

### 6. Digital signatures
ECDSA with curve P-256 and SHA-256. Generate keys → Sign → Verify. Edit the message after signing and Verify again: it fails. Signatures give **integrity and authenticity**, not secrecy. The private key is never shown.

### 7. Terminal
A simulated console. It only matches a fixed list of commands — it never runs JavaScript or shell commands.
`help`, `about`, `algorithms`, `demo aes`, `demo hash`, `demo base64`, `demo e2ee`, `clear`

---

## Package formats

**AES-256-GCM**
```json
{"alg":"AES-256-GCM","iv":"<base64 12 bytes>","ct":"<base64 ciphertext+tag>"}
```
**Password-based**
```json
{"alg":"PBKDF2-SHA256+AES-256-GCM","iter":310000,"salt":"<base64 16 bytes>","iv":"<base64 12 bytes>","ct":"<base64>"}
```
**RSA-OAEP**
```json
{"alg":"RSA-OAEP-SHA256","ct":"<base64>"}
```
Malformed JSON, missing fields, unknown algorithms and out-of-range iteration counts are rejected with an error message.

---

## Security and privacy design
- All cryptography runs locally via `crypto.subtle`. Nothing is sent anywhere.
- No analytics, trackers or third-party scripts; CSP blocks outside connections.
- No secrets in `localStorage`/`sessionStorage`. Keys live only in JS memory for the current page session.
- The workbench AES key and RSA keys are created non-extractable; the E2EE demo keys are extractable only so the *public* key can be displayed — private keys are never exported.
- User text is displayed with `textContent` / `.value`, not `innerHTML`, to avoid HTML injection.
- No secrets are written to the console.
- **Clear all** resets inputs and drops key references. JavaScript cannot guarantee physical memory erasure.

## Manual testing checklist
- [ ] **AES:** choose AES → Generate Key → Encrypt → Decrypt returns the original text.
- [ ] **Tamper:** after encrypting, click Tamper test → shows a failure message.
- [ ] **Wrong key:** refresh the page (key lost), paste the old package, Decrypt → clear error.
- [ ] **Password mode:** encrypt, paste package into the message box, decrypt with correct and wrong passwords.
- [ ] **RSA:** Generate Key → encrypt short text → decrypt; a 200-character message is rejected.
- [ ] **Encoding:** Base64 and Hex round trips; invalid hex shows an error.
- [ ] **Hashing:** SHA-256 of `abc` = `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`; SHA-384 starts `cb00753f45a35e8b`; SHA-512 starts `ddaf35a193617aba`.
- [ ] **Avalanche:** roughly 50% of bits differ.
- [ ] **E2EE:** buttons 1 → 5 in order; clicking out of order shows a helpful error; Reset clears panels.
- [ ] **Classical:** Caesar shift 3 of `Attack at dawn` → `Dwwdfn dw gdzq`; ROT13 twice returns the original.
- [ ] **Signature:** sign, verify = valid; change message, verify = invalid.
- [ ] **Terminal:** run each command; unknown command gives a harmless message.
- [ ] **Mobile:** narrow the window under 700px; the menu button appears and the layout stacks.
- [ ] **Keyboard:** Tab through controls; focus outline is visible.

## Browser compatibility
Works in current Chrome, Edge, Firefox and Safari (anything with Web Crypto, ES6+ and CSS Grid). Needs `https://` or `localhost`. Clipboard copy may be blocked by some browsers outside secure contexts.

## Limitations and caveats
- Educational demo — **not audited**, not for protecting real secrets.
- The E2EE simulator is not a full messaging protocol (no key verification, replay protection or forward secrecy).
- Keys are lost when the page is refreshed (by design), so old AES/RSA packages cannot be decrypted afterwards.
- Memory clearing in JavaScript is best-effort only.
- Planned items from the original design are not yet built (see roadmap).

## Roadmap
- [ ] Education center: lessons in English + Hinglish with mini demos
- [ ] Quiz with explanations and progress indicator
- [ ] Glossary and searchable algorithm reference
- [ ] Safe attack demos: dictionary attack on a toy list, weak vs strong password
- [ ] Downloadable example packages
- [ ] Light/dark theme toggle and toast notifications

## Disclaimer
This project is for **learning and authorized, ethical use only**. All demos use locally generated synthetic data. No real systems are targeted. Do not use it to protect production data.

**Built by — MUKU EXPLOITS**

License: add your preferred license (for example MIT) as a `LICENSE` file before publishing.
