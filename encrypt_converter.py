# ================================================================
# Ciphertext Algorithm Classification using Machine Learning
#
# Updated Model
# Algorithms classified:
#   AES
#   DES_FAMILY (DES + 3DES)
#   RC4
#   AFFINE
#
# Reason:
# DES and 3DES are statistically almost identical and
# cannot be reliably distinguished using ciphertext statistics.
# ================================================================

import pandas as pd
import numpy as np
from collections import Counter
from math import log2

from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.preprocessing import LabelEncoder

from xgboost import XGBClassifier


# ===============================
# Load dataset
# ===============================

df = pd.read_csv("ciphertext_dataset.csv")

print("Dataset size:", len(df))


# ===============================
# Merge DES and 3DES
# ===============================

df["algorithm"] = df["algorithm"].replace({
    "DES": "DES_FAMILY",
    "3DES": "DES_FAMILY"
})


# ===============================
# Feature functions
# ===============================

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

    expected = 1/256

    return np.sum(((freq - expected)**2) / expected)


def transition_matrix(data):

    transitions = np.zeros((16,16))

    for i in range(len(data)-1):

        a = data[i] % 16
        b = data[i+1] % 16

        transitions[a][b] += 1

    transitions = transitions.flatten()

    return transitions / np.sum(transitions)


def block_features(data, block_size=8):

    blocks = [data[i:i+block_size] for i in range(0, len(data), block_size)]

    entropies = []

    for block in blocks:

        counts = Counter(block)

        probs = [c/len(block) for c in counts.values()]

        ent = -sum(p*log2(p) for p in probs)

        entropies.append(ent)

    mean_entropy = np.mean(entropies)

    var_entropy = np.var(entropies)

    unique_ratio = len(set(blocks)) / len(blocks)

    return np.array([mean_entropy, var_entropy, unique_ratio])


# ===============================
# Feature extraction
# ===============================

print("Extracting features...")

features = []

for cipher in df["ciphertext"]:

    data = bytes.fromhex(cipher)

    ent = entropy(data)

    freq = byte_frequency(data)

    var = byte_variance(freq)

    chi = chi_square(freq)

    length = len(data)

    transitions = transition_matrix(data)

    block_feat = block_features(data)

    feature_vector = np.concatenate((
        [ent, var, chi, length],
        block_feat,
        freq,
        transitions
    ))

    features.append(feature_vector)


X = np.array(features)


# ===============================
# Encode labels
# ===============================

encoder = LabelEncoder()

y = encoder.fit_transform(df["algorithm"])


# ===============================
# Train test split
# ===============================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)


# ===============================
# Train model
# ===============================

print("Training model...")

model = XGBClassifier(
    n_estimators=600,
    max_depth=10,
    learning_rate=0.03,
    subsample=0.9
)

model.fit(X_train, y_train)


# ===============================
# Evaluate model
# ===============================

pred = model.predict(X_test)

print("\nClassification Report:\n")

print(classification_report(y_test, pred, target_names=encoder.classes_))

print("\nConfusion Matrix:\n")

print(confusion_matrix(y_test, pred))


# ===============================
# Prediction function
# ===============================

def predict_algorithm(ciphertext):

    data = bytes.fromhex(ciphertext)

    ent = entropy(data)

    freq = byte_frequency(data)

    var = byte_variance(freq)

    chi = chi_square(freq)

    length = len(data)

    transitions = transition_matrix(data)

    block_feat = block_features(data)

    feature = np.concatenate((
        [ent, var, chi, length],
        block_feat,
        freq,
        transitions
    )).reshape(1, -1)

    prediction = model.predict(feature)

    return encoder.inverse_transform(prediction)[0]


# ===============================
# Interactive detector
# ===============================

print("\n=================================")
print(" Ciphertext Algorithm Detector ")
print("=================================")

while True:

    user_input = input("\nEnter ciphertext in HEX (or type 'exit'): ")

    if user_input.lower() == "exit":
        break

    try:

        prediction = predict_algorithm(user_input)

        print("\nPredicted Algorithm:", prediction)

    except:

        print("Invalid HEX input.")
