# Pay-to-Multi-Signature (P2MS) Script Simulation

This repository contains Python programs to create and execute Pay-to-Multi-Signature (P2MS) scripts using the PyCryptodome package. The implementation simulates P2MS script creation and execution.

---

## Features

### 1. **Script Creation (`create.py`)**
- Generates:
  - **N** pairs of DSA 1024-bit public/private keys.
  - **M** unique DSA signatures of the fixed text: `CSCI301 Contemporary Topics in Security 2024`.
- Outputs:
  - **scriptPubKey** in `scriptPubKey_<iteration>.txt` containing public keys and required operators.
  - **scriptSig** in `scriptSig_<iteration>.txt` containing signatures.

### 2. **Script Execution (`execute.py`)**
- Reads the generated `scriptPubKey` and `scriptSig` files.
- Verifies the validity of signatures against the public keys.
- Executes the script by checking if at least **M** signatures are valid.

## How to run
python create.py
python execute.py
