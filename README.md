# Attestation Verify Demo

This project demonstrates how to encode, sign, and verify Ethereum-style attestations(signed by primuslabs) using Python.

## Prerequisites
- Python 3.8 or higher (recommended to use a virtual environment)

## Installation

1. **Clone the repository** (if not already):
   ```bash
   git clone https://github.com/xudean/attestation-verify-python-demo.git
   cd attestation-verify-python-demo
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. **Prepare your attestation JSON:**
   - Edit or replace `attestation.json` with your attestation data(signed by primuslabs).

2. **Run the demo:**
- Run demo to verify attestation:
   ```bash
   python3 attestation_sign.py
   ```
   This will:
   - Load the attestation from `attestation.json`
   - Encode the attestation
   - Attempt to recover the signer address from the signature
   - Compare the recovered signer address with the expected signer address

- Run demo to sign an app signature and verify it:
  ```bash
  python3 app_sign_and_verify.py
  ```
  This will:
  - Generate an app signature with app secret key
  - Verify the app signature