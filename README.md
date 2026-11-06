
# Applied Cryptography & PKI Security Demonstrations

A Python-based academic project developed as part of my HND Computing coursework at ABC Horizon Academy.

## Project Overview

This project demonstrates how cryptographic techniques can protect sensitive information in a fictional healthcare environment.

It explores encryption, digital certificates, authentication, and the detection of unauthorized data modifications.

## Features

### Public Key Infrastructure (PKI)
- Generates RSA-3072 private/public key pairs.
- Creates root and issuing certificate authorities.
- Issues certificates for hospital servers and administrators.

### Secure Data Transfer
- Encrypts fictional patient records using AES-256-GCM.
- Protects the AES key using RSA-OAEP.
- Uses RSA-PSS digital signatures to verify authenticity.
- Demonstrates rejection of modified data and forged signatures.

### Certificate-Based Authentication
- Demonstrates administrator authentication using digital certificates.
- Verifies possession of the corresponding private key.
- Simulates certificate revocation.

### Cryptanalysis
- Compares AES-ECB and AES-GCM.
- Demonstrates weaknesses in deliberately small RSA keys.

## Technologies

- Python
- Cryptography library
- SymPy
- RSA, AES-GCM, PKI and X.509 certificates

## Running the Project

Install dependencies:

```bash
python -m pip install cryptography sympy
```

Open the project folder:

```bash
cd MHG_M4_Implementation
```

Run the demonstrations:

```bash
python run_all.py
```

The scripts generate demonstration keys, certificates and output files locally. These files should not be committed to GitHub.

## Important

This project is intended for educational purposes only.

It uses fictional patient data and demonstrates cryptographic concepts. It is not a production-ready healthcare security system.

