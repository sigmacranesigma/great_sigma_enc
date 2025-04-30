#!/usr/bin/env python3
"""
mlpqte_enc.py

Usage:
  python mlpqte_enc.py enc <recipient_pub.pem> <infile> <outfile>
"""
import sys, os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from Crypto.Cipher import ChaCha20_Poly1305

def enc(public_key_path, infile, outfile):
    pub = serialization.load_pem_public_key(open(public_key_path, "rb").read())

    # Random symmetric key
    sym_key = os.urandom(32)
    nonce = os.urandom(24)
    aead = ChaCha20_Poly1305.new(key=sym_key, nonce=nonce)
    plaintext = open(infile, "rb").read()
    ciphertext2, tag = aead.encrypt_and_digest(plaintext)

    # Encrypt symmetric key using RSA
    enc_key = pub.encrypt(sym_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))

    with open(outfile, "wb") as f:
        f.write(len(enc_key).to_bytes(2, 'big'))
        f.write(enc_key)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext2)

    print(f"[+] Encrypted → {outfile}")

if __name__=="__main__":
    if len(sys.argv)!=5 or sys.argv[1]!="enc":
        print(__doc__)
        sys.exit(1)
    _, _, pub, inp, out = sys.argv
    enc(pub, inp, out)