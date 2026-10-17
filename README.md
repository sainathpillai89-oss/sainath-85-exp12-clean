# Cryptography Lab Experiments

## Project by: Sainath Pillai

This repository contains the implementation and output of cryptography laboratory experiments performed using Python and PyCryptodome.

The project demonstrates both classical and modern cryptographic techniques, including:
- Caesar Cipher
- Affine Cipher
- Vigenere Cipher
- Euclidean Algorithm and Modular Inverse
- Congruence, Fermat's Little Theorem, and CRT
- AES-ECB and AES-CBC encryption and decryption

## Experiments Included

1. Experiment 12A — AES Security Analysis: ECB vs CBC
2. Experiment 12B — Design and Analysis of a Secure Encryption Scheme

---

## Experiment 12A — AES Security Analysis: ECB vs CBC

### Objective
To study the difference between AES in ECB and CBC mode and analyze how repeated plaintext patterns are revealed in ECB ciphertext.

### Concepts Covered
- AES-128 encryption and decryption
- ECB mode behavior
- CBC mode with IV chaining
- PKCS#7 padding
- block-level comparison and security analysis

### Example Input
```text
1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF
```

### Observation
- ECB shows repeated ciphertext blocks for repeated plaintext blocks.
- CBC hides repeated pattern information because each block depends on the previous ciphertext block.

### Result
The experiment verifies that ECB leaks patterns, while CBC provides better confidentiality for repeated data.

---

## Experiment 12B — Design and Analysis of a Secure Encryption Scheme

### Objective
To implement classical cryptographic techniques and mathematical foundations used in secure encryption, along with AES-CBC.

### Included Techniques
- Caesar Cipher
- Euclidean Algorithm
- Modular Inverse
- Affine Cipher
- Vigenere Cipher
- Congruence Relation
- Fermat's Little Theorem
- Chinese Remainder Theorem
- AES-CBC

### Result
All implemented cryptographic operations were successfully verified and decrypted correctly.

---

## Requirements

Install the required Python package:

```bash
python -m pip install -r requirements.txt
```

The project uses:
- Python 3.x
- PyCryptodome

---

## How to Run

### Experiment 12A
```bash
python experiment_12_aes_ecb_cbc/aes_ecb_cbc.py
```

### Experiment 12B
```bash
python experiment_2b_secure_encryption/experiment2_cryptography.py
```

---

## Project Structure

```text
cryptography-lab-experiment12/
├── README.md
├── .gitignore
├── requirements.txt
├── experiment_12_aes_ecb_cbc/
│   ├── aes_ecb_cbc.py
│   └── output.txt
├── experiment_2b_secure_encryption/
│   ├── experiment2_cryptography.py
│   └── output.txt
└──
```

---

## Summary

This repository demonstrates a clear understanding of cryptographic principles and the practical implementation of encryption algorithms, from classical substitution ciphers to modern AES block cipher modes.

## License

This project is for academic and learning purposes.
