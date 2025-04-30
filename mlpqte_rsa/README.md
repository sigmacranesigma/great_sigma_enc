# MLPQTE (RSA Edition) - Multi-Layer Threshold Encryption

This is a strong hybrid encryption system that combines:
- RSA 4096-bit key exchange
- XChaCha20-Poly1305 for authenticated encryption
- Shamir Secret Sharing via `cryptography`

## Usage

1. Generate RSA keypair and split master key:
```
python mlpqte_gen.py genkeys 5 3
```

2. Reconstruct master key (if needed):
```python
from cryptography.hazmat.primitives.secret_sharing import Shamir
import base64

shares = []
for i in [1,2,3]:
    with open(f"shares/share_{i}.b64") as f:
        part = f.read().strip().split(":")
        shares.append((int(part[0]), base64.b64decode(part[1])))

key = Shamir.combine(shares)
print(key.hex())
```

3. Encrypt and decrypt files:
```
python mlpqte_enc.py enc public.pem secret.txt encrypted.bin
python mlpqte_dec.py dec private.pem encrypted.bin decrypted.txt
```