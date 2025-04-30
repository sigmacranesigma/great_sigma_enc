#!/usr/bin/env python3
"""
mlpqte_dec.py

Usage:
  python mlpqte_dec.py dec <private.pem> <infile> <outfile>
"""
import sys, os
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from Crypto.Cipher import ChaCha20_Poly1305

def dec(private_key_path, infile, outfile):
    pri = serialization.load_pem_private_key(open(private_key_path, "rb").read(), password=None)
    blob = open(infile, "rb").read()
    l = int.from_bytes(blob[:2], 'big')
    enc_key = blob[2:2+l]
    nonce = blob[2+l:2+l+24]
    tag = blob[2+l+24:2+l+40]
    ct2 = blob[2+l+40:]

    sym_key = pri.decrypt(enc_key, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None))

    aead = ChaCha20_Poly1305.new(key=sym_key, nonce=nonce)
    plaintext = aead.decrypt_and_verify(ct2, tag)
    with open(outfile, "wb") as f:
        f.write(plaintext)
    print(f"[+] Decrypted → {outfile}")

if __name__=="__main__":
    if len(sys.argv)!=5 or sys.argv[1]!="dec":
        print(__doc__)
        sys.exit(1)
    _, _, pri, inp, out = sys.argv
    dec(pri, inp, out)