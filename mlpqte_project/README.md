# MLPQTE - Multi-Layer Post-Quantum Threshold Encryption

MLPQTE is an experimental encryption system that combines:
- Kyber post-quantum KEM
- XChaCha20-Poly1305 AEAD
- Shamir Secret Sharing for master key

## Usage

1. Generate keypair and split master:
```
python mlpqte_gen.py genkeys 5 3
```

2. Reconstruct master from 3 of 5 shares:
```python
from secretsharing import PlaintextToHexSecretSharer as S
print(S.recover_secret([open('shares/share_1.txt').read(), open('shares/share_2.txt').read(), open('shares/share_3.txt').read()]))
```
Copy that result and set it as an environment variable:

**Windows (Command Prompt):**
```
set MLPQTE_MASTER=your_hex_key_here
```

3. Encrypt/decrypt files:
```
python mlpqte_enc.py enc public.pem message.txt message.enc
python mlpqte_dec.py dec private.pem message.enc decrypted.txt
```