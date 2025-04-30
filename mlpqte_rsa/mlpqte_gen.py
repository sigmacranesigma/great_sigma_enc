#!/usr/bin/env python3
"""
mlpqte_gen.py

Usage:
  python mlpqte_gen.py genkeys <n> <t>
"""
import os, sys, base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.secret_sharing import Shamir

def genkeys(n, t):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    public_key = private_key.public_key()

    with open("private.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open("public.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    os.chmod("private.pem", 0o600)
    print("[+] RSA keypair generated.")

    # Generate 32-byte master key
    master_key = os.urandom(32)
    shares = Shamir.split(t, n, master_key)

    os.makedirs("shares", exist_ok=True)
    for idx, (x, y) in enumerate(shares, start=1):
        with open(f"shares/share_{idx}.b64", "w") as f:
            f.write(f"{x}:{base64.b64encode(y).decode()}")
    print(f"[+] Master key split into {n} shares (threshold={t}).")

if __name__ == "__main__":
    if len(sys.argv) != 4 or sys.argv[1] != "genkeys":
        print(__doc__)
        sys.exit(1)
    _, _, n, t = sys.argv
    genkeys(int(n), int(t))