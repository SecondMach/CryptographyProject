# app.py
from flask import Flask, render_template, request, jsonify
import joblib
import numpy as np
from collections import Counter
from math import log2
import time
from Crypto.Cipher import AES, DES, ARC4
from Crypto.Random import get_random_bytes

app = Flask(__name__)

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


def byte_variance(freq):
    return np.var(freq)


def chi_square(freq):
    expected = 1 / 256
    return np.sum(((freq - expected) ** 2) / expected)


def transition_matrix(data):
    transitions = np.zeros((16, 16))
    for i in range(len(data) - 1):
        a = data[i] % 16
        b = data[i + 1] % 16
        transitions[a][b] += 1
    transitions = transitions.flatten()
    return transitions / np.sum(transitions)


def block_features(data, block_size=8):
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    entropies = []

    for block in blocks:
        counts = Counter(block)
        probs = [c / len(block) for c in counts.values()]
        ent = -sum(p * log2(p) for p in probs)
        entropies.append(ent)

    return np.array([
        np.mean(entropies),
        np.var(entropies),
        len(set(blocks)) / len(blocks)
    ])


def extract_features(ciphertext):
    data = bytes.fromhex(ciphertext)

    ent = entropy(data)
    freq = byte_frequency(data)
    var = byte_variance(freq)
    chi = chi_square(freq)
    length = len(data)
    transitions = transition_matrix(data)
    block_feat = block_features(data)

    return np.concatenate((
        [ent, var, chi, length],
        block_feat,
        freq,
        transitions
    )).reshape(1, -1)

def entropy_chunks(data, chunk_size=16):
    chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    return [entropy(chunk) for chunk in chunks if len(chunk) > 0]

# ------------------ Encoder Functions ------------------ #
def affine_encrypt(text: str, a: int = 5, b: int = 8) -> bytes:
    return bytes([(a * ord(c) + b) % 256 for c in text])

def encrypt_text(plaintext: str, algorithm: str) -> str:
    data = plaintext.encode()
    
    # Minimum input warning for decoder (~32 bytes)
    if len(data) < 32:
        raise ValueError("Input too short. Use at least ~6–8 words.")

    if algorithm == "AES":
        key = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_ECB)
        while len(data) % 16 != 0:
            data += b" "
        encrypted = cipher.encrypt(data)

    elif algorithm == "DES_FAMILY":
        key = get_random_bytes(8)
        cipher = DES.new(key, DES.MODE_ECB)
        while len(data) % 8 != 0:
            data += b" "
        encrypted = cipher.encrypt(data)

    elif algorithm == "RC4":
        key = get_random_bytes(16)
        cipher = ARC4.new(key)
        encrypted = cipher.encrypt(data)

    elif algorithm == "AFFINE":
        encrypted = affine_encrypt(plaintext)

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

        # Validate hex input
        try:
            raw_bytes = bytes.fromhex(ciphertext)
        except ValueError:
            return jsonify({"error": "Invalid hex input"}), 400

        start = time.time()

        # Extract features
        features = extract_features(ciphertext)

        # Model prediction
        prediction = model.predict(features)
        probs = model.predict_proba(features)

        result = encoder.inverse_transform(prediction)[0]
        confidence = float(np.max(probs))

        end = time.time()
        latency = (end - start) * 1000  # ms

        # Additional metrics
        ent = entropy(raw_bytes)
        chunk_entropy = entropy_chunks(raw_bytes)
        freq = byte_frequency(raw_bytes)
        variance = byte_variance(freq)

        return jsonify({
            "prediction": result,
            "confidence": confidence,
            "entropy": round(ent, 4),
            "block_size": 8,
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
import os

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
