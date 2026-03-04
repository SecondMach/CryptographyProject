import random
import string
import pandas as pd
from Crypto.Cipher import AES, DES, DES3, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


# ===============================
# Parameters
# ===============================

SAMPLES_PER_ALGO = 5000
PLAINTEXT_LENGTH = 64


# ===============================
# Random plaintext generator
# ===============================

def generate_plaintext(length=PLAINTEXT_LENGTH):
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length)).encode()


# ===============================
# AES Encryption
# ===============================

def encrypt_aes(plaintext):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(plaintext, 16)
    ciphertext = cipher.encrypt(padded)
    return ciphertext.hex()


# ===============================
# DES Encryption
# ===============================

def encrypt_des(plaintext):
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(plaintext, 8)
    ciphertext = cipher.encrypt(padded)
    return ciphertext.hex()


# ===============================
# 3DES Encryption
# ===============================

def encrypt_3des(plaintext):
    key = DES3.adjust_key_parity(get_random_bytes(24))
    cipher = DES3.new(key, DES3.MODE_ECB)
    padded = pad(plaintext, 8)
    ciphertext = cipher.encrypt(padded)
    return ciphertext.hex()


# ===============================
# RC4 Stream Cipher
# ===============================

def encrypt_rc4(plaintext):
    key = get_random_bytes(16)
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(plaintext)
    return ciphertext.hex()


# ===============================
# Affine Cipher
# ===============================

def affine_encrypt(text, a=5, b=8):
    result = ""
    for char in text.decode():
        if char.isalpha():
            x = ord(char.lower()) - ord('a')
            enc = (a * x + b) % 26
            result += chr(enc + ord('a'))
        else:
            result += char
    return result.encode().hex()


# ===============================
# Dataset generation
# ===============================

dataset = []

print("Generating AES samples...")
for _ in range(SAMPLES_PER_ALGO):
    pt = generate_plaintext()
    ct = encrypt_aes(pt)
    dataset.append([ct, "AES"])

print("Generating DES samples...")
for _ in range(SAMPLES_PER_ALGO):
    pt = generate_plaintext()
    ct = encrypt_des(pt)
    dataset.append([ct, "DES"])

print("Generating 3DES samples...")
for _ in range(SAMPLES_PER_ALGO):
    pt = generate_plaintext()
    ct = encrypt_3des(pt)
    dataset.append([ct, "3DES"])

print("Generating RC4 samples...")
for _ in range(SAMPLES_PER_ALGO):
    pt = generate_plaintext()
    ct = encrypt_rc4(pt)
    dataset.append([ct, "RC4"])

print("Generating Affine samples...")
for _ in range(SAMPLES_PER_ALGO):
    pt = generate_plaintext()
    ct = affine_encrypt(pt)
    dataset.append([ct, "AFFINE"])


# ===============================
# Convert to DataFrame
# ===============================

df = pd.DataFrame(dataset, columns=["ciphertext", "algorithm"])

# Shuffle dataset
df = df.sample(frac=1).reset_index(drop=True)

# Save dataset
df.to_csv("ciphertext_dataset.csv", index=False)

print("\nDataset generated successfully!")
print("Total samples:", len(df))
print("Saved as ciphertext_dataset.csv")
