# 🔐 Simple XOR Encryption/Decryption CLI Tool (Rust)

## 🛡️ Why This Matters: Protecting Sensitive Data

In today’s world, **data at rest must be encrypted**. Whether it’s credentials, personal information, or confidential records, storing sensitive data in plain text is a **critical security risk**.

> Even if a hacker gains access to your system, encrypted data will remain unreadable without the key.

This tool helps enforce that practice by making it **easy to encrypt and decrypt text data locally**, using a simple XOR cipher.

---

## 🚀 What This Tool Does

This command-line Rust program allows you to:
- 🔏 Encrypt any text using a secret key and save it as a `.txt` file
- 🔓 Decrypt an encrypted `.txt` file using the same secret key

All encrypted data is stored as a **hex-encoded string**, providing safe storage in files.

---

## 📋 Features

- File-based XOR encryption and decryption
- Intelligent filename sanitization based on user input
- Fully interactive terminal prompts
- Built-in protection from invalid inputs

---

## 🧰 Dependencies

This tool uses only the **Rust Standard Library** — no external dependencies required!

---

## 📦 How to Set Up and Run

### ✅ 1. Clone the Repository

```bash
git clone https://github.com/deekshithreddy1/MyRustApp.git
cd MyRustApp

cargo build --release

cargo run
