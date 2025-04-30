import tkinter as tk
from tkinter import filedialog, messagebox
import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from Crypto.Cipher import ChaCha20_Poly1305
import random


# Helper function to generate a polynomial for Shamir Secret Sharing
def generate_polynomial(secret, degree):
    coefficients = [secret]
    for _ in range(degree - 1):
        coefficients.append(random.randint(1, 1000))
    return coefficients


# Helper function for Shamir's Secret Sharing
def evaluate_polynomial(coefficients, x):
    return sum(c * (x ** i) for i, c in enumerate(coefficients)) % 257


# Split the secret into shares (Shamir Secret Sharing)
def shamir_split(secret, n, t):
    if t > n:
        raise ValueError("Threshold can't be greater than total shares")

    polynomial = generate_polynomial(secret, t)
    shares = []
    for i in range(1, n + 1):
        share = (i, evaluate_polynomial(polynomial, i))
        shares.append(share)
    return shares


# Combine shares to recover the secret
def shamir_combine(shares, t):
    if len(shares) < t:
        raise ValueError(f"Need at least {t} shares to recover the secret.")

    def lagrange_interpolation(shares, x):
        result = 0
        for i, (xi, yi) in enumerate(shares):
            numerator = 1
            denominator = 1
            for j, (xj, _) in enumerate(shares):
                if i != j:
                    numerator *= (x - xj)
                    denominator *= (xi - xj)
            result += yi * numerator // denominator
        return result % 257

    secret = lagrange_interpolation(shares, 0)
    return secret


# Function to generate RSA keys and secret shares
def gen_keys():
    try:
        n = int(entry_n.get())
        t = int(entry_t.get())
        if t > n:
            raise ValueError("Threshold can't be greater than total shares")

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

        os.makedirs("shares", exist_ok=True)
        master_key = os.urandom(32)
        shares = shamir_split(int.from_bytes(master_key, byteorder='big'), n, t)  # Convert master key to integer
        for idx, (x, y) in enumerate(shares, start=1):
            with open(f"shares/share_{idx}.b64", "w") as f:
                f.write(f"{x}:{base64.b64encode(bytes([y])).decode()}")  # Convert y to bytes
        status.set("✅ Keypair + shares generated")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Encrypt a file
def encrypt_file():
    try:
        pub_file = filedialog.askopenfilename(title="Select Public Key", filetypes=[("PEM files", "*.pem")])
        in_file = filedialog.askopenfilename(title="Select File to Encrypt")
        out_file = filedialog.asksaveasfilename(title="Save Encrypted File As", defaultextension=".bin")

        pub = serialization.load_pem_public_key(open(pub_file, "rb").read())
        sym_key = os.urandom(32)
        nonce = os.urandom(24)
        aead = ChaCha20_Poly1305.new(key=sym_key, nonce=nonce)
        plaintext = open(in_file, "rb").read()
        ct, tag = aead.encrypt_and_digest(plaintext)

        enc_key = pub.encrypt(sym_key, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(), label=None))

        with open(out_file, "wb") as f:
            f.write(len(enc_key).to_bytes(2, 'big'))
            f.write(enc_key)
            f.write(nonce)
            f.write(tag)
            f.write(ct)
        status.set(f"✅ Encrypted: {os.path.basename(out_file)}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


# Decrypt a file
def decrypt_file():
    try:
        pri_file = filedialog.askopenfilename(title="Select Private Key", filetypes=[("PEM files", "*.pem")])
        in_file = filedialog.askopenfilename(title="Select File to Decrypt")
        out_file = filedialog.asksaveasfilename(title="Save Decrypted File As")

        pri = serialization.load_pem_private_key(open(pri_file, "rb").read(), password=None)
        blob = open(in_file, "rb").read()
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
        with open(out_file, "wb") as f:
            f.write(plaintext)
        status.set(f"✅ Decrypted: {os.path.basename(out_file)}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


root = tk.Tk()
root.title("MLPQTE - RSA Encryption GUI")
root.geometry("450x250")
status = tk.StringVar()

tk.Label(root, text="Shamir: Total Shares (n)").pack()
entry_n = tk.Entry(root)
entry_n.insert(0, "5")
entry_n.pack()

tk.Label(root, text="Shamir: Threshold (t)").pack()
entry_t = tk.Entry(root)
entry_t.insert(0, "3")
entry_t.pack()

tk.Button(root, text="🔐 Generate Keys + Shares", command=gen_keys).pack(pady=5)
tk.Button(root, text="📦 Encrypt File", command=encrypt_file).pack(pady=5)
tk.Button(root, text="🔓 Decrypt File", command=decrypt_file).pack(pady=5)

tk.Label(root, textvariable=status, fg="green").pack(pady=10)
root.mainloop()
