// script.js
document.addEventListener("DOMContentLoaded", () => {
    const textarea = document.getElementById("inputText");
    const buffer = document.getElementById("bufferCount");
    const analyzeBtn = document.getElementById("analyzeBtn");
    const encryptBtn = document.querySelector("button[onclick='encryptText()']");

    // Update buffer count + reset UI on typing
    if (textarea && buffer) {
        textarea.addEventListener("input", () => {
            const length = textarea.value.length;
            buffer.innerText = `Buffer: ${length} / 65536`;

            // Reset UI if decoder page
            resetUI();

            // Reset encoder output
            const output = document.getElementById("outputText");
            if (output) output.value = "";
        });
    }

    // Attach analyze button handler (decoder.html)
    if (analyzeBtn) {
        analyzeBtn.addEventListener("click", analyzeText);
    }

    // Attach encrypt button handler (encoder.html)
    if (encryptBtn) {
        encryptBtn.addEventListener("click", encryptText);
    }

    // Attach copy button handler
    const copyBtn = document.getElementById("copyBtn");
    if (copyBtn) {
        copyBtn.addEventListener("click", copyText);
    }
});

// ------------------ ENCODER ------------------ //
async function encryptText() {
    const textArea = document.getElementById("inputText");
    const algoSelect = document.getElementById("algorithmSelect");
    const outputArea = document.getElementById("outputText");

    let plaintext = textArea ? textArea.value.trim() : "";
    const algorithm = algoSelect ? algoSelect.value : "";

    if (!plaintext) {
        alert("Please enter plaintext to encrypt");
        return;
    }

    if (!algorithm) {
        alert("Please select an encryption algorithm");
        return;
    }

    try {
        const response = await fetch("/encrypt", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ plaintext, algorithm })
        });

        const data = await response.json();

        if (!response.ok || data.error) {
            throw new Error(data.error || "Server error");
        }

        if (outputArea) outputArea.value = data.ciphertext;

    } catch (err) {
        console.error(err);
        alert("Encryption Error: " + err.message);
    }
}

// ------------------ COPY ------------------ //
function copyText() {
    const outputArea = document.getElementById("outputText");
    if (!outputArea || !outputArea.value) return;

    navigator.clipboard.writeText(outputArea.value)
        .then(() => {
            const label = document.getElementById("copyTextLabel");
            if (label) label.innerText = "Copied!";
            setTimeout(() => { if(label) label.innerText = "Copy"; }, 1500);
        })
        .catch(err => console.error("Copy failed", err));
}

// ------------------ DECODER ------------------ //
async function analyzeText() {
    const textArea = document.getElementById("inputText");
    const btn = document.getElementById("analyzeBtn");

    let text = textArea ? textArea.value : "";

    // Clean input (hex only)
    text = text.replace(/[^0-9a-fA-F]/g, "");

    if (!text) {
        alert("Please enter ciphertext (hex)");
        return;
    }
    if (text.length % 2 !== 0) {
        alert("Hex must have even length");
        return;
    }

    if (btn) {
        btn.innerText = "Analyzing...";
        btn.disabled = true;
    }

    try {
        const response = await fetch("/predict", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ciphertext: text })
        });

        const data = await response.json();

        if (!response.ok || data.error) {
            throw new Error(data.error || "Server error");
        }

        updateAnalysisUI(data);

    } catch (err) {
        console.error(err);
        alert("Error: " + err.message);
    } finally {
        if (btn) {
            btn.innerText = "Analyze Neural Signature";
            btn.disabled = false;
        }
    }
}

// ------------------ DECODER UI ------------------ //
function updateAnalysisUI(data) {
    const resultPanel = document.getElementById("resultPanel");
    const algo = document.getElementById("algorithmResult");
    const conf = document.getElementById("confidenceResult");
    const bar = document.getElementById("confidenceBar");
    const summary = document.getElementById("summaryResult");

    if (resultPanel) resultPanel.classList.remove("hidden");
    if (algo) algo.innerText = data.prediction || "---";
    if (conf && data.confidence !== undefined) {
        const percent = (data.confidence * 100).toFixed(2);
        conf.innerText = percent + "%";
        if (bar) bar.style.width = percent + "%";
    }
    if (summary) {
        summary.innerText =
            `Entropy: ${data.entropy} bits/byte\n` +
            `Variance: ${data.variance.toFixed(6)}\n` +
            `Prediction: ${data.prediction} (${(data.confidence * 100).toFixed(2)}%)`;
    }
}

function resetUI() {
    const resultPanel = document.getElementById("resultPanel");
    const algo = document.getElementById("algorithmResult");
    const conf = document.getElementById("confidenceResult");
    const bar = document.getElementById("confidenceBar");
    const summary = document.getElementById("summaryResult");

    if (resultPanel) resultPanel.classList.add("hidden");
    if (algo) algo.innerText = "---";
    if (conf) conf.innerText = "---";
    if (bar) bar.style.width = "0%";
    if (summary) summary.innerText = "";
}
