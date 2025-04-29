#!/usr/bin/env python3
"""
mlpqte_dec.py

Usage:
  ./mlpqte_dec.py dec <private.pem> <infile> <outfile>
"""
import sys, os
from pqcrypto.kem.kyber512 import decrypt as kem_decap
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

def dec(priv_path, infile, outfile):
    pri = open(priv_path,"rb").read()
    blob = open(infile,"rb").read()
    l = int.from_bytes(blob[:2],'big')
    ct1 = blob[2:2+l]
    nonce = blob[2+l:2+l+24]
    tag   = blob[2+l+24:2+l+40]
    ct2   = blob[2+l+40:]
    shared = kem_decap(ct1, pri)
    data_key = HKDF(shared, 32, b"", SHA256, 1)
    aead = ChaCha20_Poly1305.new(key=data_key, nonce=nonce)
    plaintext = aead.decrypt_and_verify(ct2, tag)
    with open(outfile,"wb") as f: f.write(plaintext)
    print(f"[+] Decrypted → {outfile}")

if __name__=="__main__":
    if len(sys.argv)!=5 or sys.argv[1]!="dec":
        print(__doc__); sys.exit(1)
    _, mode, pri, inp, out = sys.argv
    dec(pri, inp, out)