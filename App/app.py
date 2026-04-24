# app.py
from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
from collections import Counter
from math import log2
import time
import os

from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

app = Flask(__name__)

# ------------------ Load Model ------------------ #

# Load your trained model and encoder
model = joblib.load("model.pkl")
encoder = joblib.load("encoder.pkl")

# ------------------ Feature Functions ------------------ #

def entropy(data):
    counts = Counter(data)
    probs = [c / len(data) for c in counts.values()]
    return -sum(p * log2(p) for p in probs)

def byte_frequency(data):
    freq = np.zeros(256)
    for b in data:
        freq[b] += 1
    return freq / len(data)

def block_repetition(data, block_size=16):
    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]
    if len(blocks) == 0:
        return 0
    return 1 - (len(set(blocks)) / len(blocks))

def autocorrelation(data):
    if len(data) < 2:
        return 0.0

    arr = np.frombuffer(data, dtype=np.uint8).astype(np.float64)

    if np.std(arr) == 0:
        return 0.0

    return float(np.corrcoef(arr[:-1], arr[1:])[0, 1])

def extract_features(ciphertext):
    data = bytes.fromhex(ciphertext)

    arr = np.frombuffer(data, dtype=np.uint8)

    ent = entropy(data)

    # frequency
    freq = np.zeros(256)
    for b in arr:
        freq[b] += 1
    freq = freq / len(arr)

    rep = block_repetition(data)
    auto = autocorrelation(data)
    length = len(data)

    return np.concatenate((
        [ent, rep, auto, length],
        freq
    )).reshape(1, -1)

def entropy_chunks(data, chunk_size=16):
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    return [entropy(chunk) for chunk in chunks if len(chunk) > 0]

# ------------------ Encoder Functions ------------------ #

def affine_encrypt_dataset_style(text, a=5, b=8):
    result = ""
    for char in text:
        if char.isalpha():
            x = ord(char.lower()) - ord('a')
            enc = (a * x + b) % 26
            result += chr(enc + ord('a'))
        else:
            result += char
    return result.encode()


def encrypt_text(plaintext: str, algorithm: str) -> str:
    plaintext = ''.join(c for c in plaintext if c.isalnum() or c.isspace())

    data = plaintext.encode()

    if len(data) < 32:
        raise ValueError("Use at least ~6–8 words (minimum 32 characters).")

    if algorithm == "AES":
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_ECB)
        encrypted = cipher.encrypt(pad(data, 16))

    elif algorithm == "DES_FAMILY":
        key = get_random_bytes(8)
        cipher = DES.new(key, DES.MODE_ECB)
        encrypted = cipher.encrypt(pad(data, 8))

    elif algorithm == "RC4":
        key = get_random_bytes(16)
        cipher = ARC4.new(key)
        encrypted = cipher.encrypt(data)

    elif algorithm == "AFFINE":
        encrypted = affine_encrypt_dataset_style(plaintext)

    else:
        raise ValueError("Unknown algorithm")

    return encrypted.hex()

# ------------------ Routes ------------------ #

@app.route("/")
def dashboard():
    return render_template("homepage.html")

@app.route("/decoder")
def decoder_page():
    return render_template("decoder.html")

@app.route("/encoder")
def encoder_page():
    return render_template("encoder.html")


# ------------------ Prediction API ------------------ #

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        ciphertext = data.get("ciphertext", "").strip()

        if not ciphertext:
            return jsonify({"error": "No ciphertext provided"}), 400

        # Validate hex
        try:
            raw_bytes = bytes.fromhex(ciphertext)
        except ValueError:
            return jsonify({"error": "Invalid hex input"}), 400

        start = time.time()

        # Feature extraction
        features = extract_features(ciphertext)

        # Model prediction
        prediction = model.predict(features)
        probs = model.predict_proba(features)

        result = encoder.inverse_transform(prediction)[0]
        confidence = float(np.max(probs))

        if result in ["AES", "RC4"] and confidence < 0.75:
            result = "AES/RC4 (Ambiguous)"

        end = time.time()
        latency = (end - start) * 1000

        # Extra metrics (for UI)
        ent = entropy(raw_bytes)
        chunk_entropy = entropy_chunks(raw_bytes)
        freq = byte_frequency(raw_bytes)
        variance = np.var(freq)

        return jsonify({
            "prediction": result,
            "confidence": confidence,
            "entropy": round(ent, 4),
            "latency": round(latency, 2),
            "length": len(raw_bytes),
            "chunk_entropy": chunk_entropy[:20],
            "byte_freq": freq.tolist(),
            "variance": float(variance)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ------------------ Encoder API ------------------ #

@app.route("/encrypt", methods=["POST"])
def encrypt():
    try:
        data = request.json
        plaintext = data.get("plaintext", "").strip()
        algorithm = data.get("algorithm", "").strip()

        if not plaintext or not algorithm:
            return jsonify({"error": "Plaintext and algorithm are required"}), 400

        ciphertext = encrypt_text(plaintext, algorithm)
        return jsonify({"ciphertext": ciphertext})

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ------------------ Run ------------------ #

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
