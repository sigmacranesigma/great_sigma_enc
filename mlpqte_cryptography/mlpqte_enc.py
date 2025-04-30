#!/usr/bin/env python3
"""
mlpqte_enc.py

Usage:
  ./mlpqte_enc.py enc <recipient_pub.pem> <infile> <outfile>
"""
import sys, os
from pqcrypto.kem.kyber512 import encrypt as kem_encap
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

def enc(public_key_path, infile, outfile):
    pub = open(public_key_path,"rb").read()
    ct1, shared = kem_encap(pub)
    data_key = HKDF(shared, 32, b"", SHA256, 1)
    aead = ChaCha20_Poly1305.new(key=data_key, nonce=os.urandom(24))
    plaintext = open(infile,"rb").read()
    ciphertext2, tag = aead.encrypt_and_digest(plaintext)
    with open(outfile,"wb") as f:
        f.write(len(ct1).to_bytes(2,'big'))
        f.write(ct1)
        f.write(aead.nonce)
        f.write(tag)
        f.write(ciphertext2)
    print(f"[+] Encrypted → {outfile}")

if __name__=="__main__":
    if len(sys.argv)!=5 or sys.argv[1]!="enc":
        print(__doc__); sys.exit(1)
    _, mode, pub, inp, out = sys.argv
    enc(pub, inp, out)