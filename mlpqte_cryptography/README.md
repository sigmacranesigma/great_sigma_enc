# MLPQTE (Cryptography Edition) - Multi-Layer Post-Quantum Threshold Encryption

MLPQTE is an experimental encryption system that combines:
- Kyber post-quantum KEM
- XChaCha20-Poly1305 AEAD
- Shamir Secret Sharing using `cryptography`

## Usage

1. Generate keypair and split master:
```
python mlpqte_gen.py genkeys 5 3
```

2. Reconstruct master from 3 of 5 shares:
```python
from cryptography.hazmat.primitives.secret_sharing import Shamir
import base64

shares = []
for i in [1,2,3]:
    with open(f"shares/share_{i}.b64") as f:
        part = f.read().strip().split(":")
        shares.append((int(part[0]), base64.b64decode(part[1])))

key = Shamir.combine(shares)
print(key.hex())  # ← set this in MLPQTE_MASTER
```

3. Encrypt/decrypt files:
```
set MLPQTE_MASTER=your_hex_key_here
python mlpqte_enc.py enc public.pem input.txt encrypted.bin
python mlpqte_dec.py dec private.pem encrypted.bin decrypted.txt
```