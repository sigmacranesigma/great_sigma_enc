#!/usr/bin/env python3
"""
mlpqte_gen.py

Usage:
  ./mlpqte_gen.py genkeys <n> <t>  
"""
import os, sys
from secretsharing import PlaintextToHexSecretSharer
from pqcrypto.kem.kyber512 import generate_keypair
from Crypto.Random import get_random_bytes

def genkeys(n, t):
    public, private = generate_keypair()
    with open("public.pem","wb") as f: f.write(public)
    with open("private.pem","wb") as f:
        f.write(private)
    os.chmod("private.pem",0o600)
    print("[+] PQ keypair generated.")

    master = get_random_bytes(32)
    hex_master = master.hex()
    shares = PlaintextToHexSecretSharer.split_secret(hex_master, t, n)
    os.makedirs("shares", exist_ok=True)
    for idx, share in enumerate(shares, start=1):
        with open(f"shares/share_{idx}.txt","w") as f:
            f.write(share)
    print(f"[+] Master key split into {n} shares (threshold={t}).")

if __name__=="__main__":
    if len(sys.argv)!=4 or sys.argv[1]!="genkeys":
        print(__doc__); sys.exit(1)
    _,_, n, t = sys.argv
    genkeys(int(n), int(t))