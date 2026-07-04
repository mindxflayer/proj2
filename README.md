# PasteGuard: The Intelligent AI Data Loss Prevention Extension

**PasteGuard** is a zero-dependency, local-first Chrome extension that detects, alerts, and blocks sensitive credentials, API keys, database connection strings, PII, and proprietary code/content **before** they are accidentally sent to AI assistants (ChatGPT, Claude, Gemini, Copilot, Perplexity).

---

## Why PasteGuard is Completely Unique

While generic credential blockers rely on simple regular expressions or ping external API servers to scan your text, PasteGuard introduces a paradigm shift. It operates an advanced **hybrid regex + local machine learning pipeline** entirely inside your browser sandbox. 

Here is what makes PasteGuard truly exceptional:

### 1. Zero-Server Local Machine Learning Inference
Most extensions either miss complex semantic leaks or send your prompts to third-party servers for NLP analysis, introducing a massive security vulnerability. PasteGuard runs **local TF-IDF vectorization and Logistic Regression classification directly in the JavaScript runtime**.
- The model (5,000 vocabulary unigram/bigram features, IDF weights, and coefficients) is compiled into a local, lightweight JSON bundle (`model_weights.json`).
- Predictions execute locally in `< 2ms` with **zero network requests**, ensuring your data never leaves your machine.

### 2. Feature-Importance-Based Auto-Redaction
When PasteGuard intercepts a prompt, it doesn't just lock the input and leave you stranded. By clicking the floating **Auto-Redact** button, PasteGuard:
1. Replaces exact regex matches (like AWS keys or database strings) with standardized placeholders.
2. Identifies high-weight vocabulary terms inside the prompt that drove the positive ML classification (e.g., `cfo`, `salary`, `acquisition`) and redacts only those specific indicator terms.
3. This dynamically drops the sensitive probability score, **safely unlocking the compose send button** while preserving the context of your prompt!

### 3. Deep Rich-Text Editor Compatibility
Unlike older extensions that break when interacting with modern web frameworks, PasteGuard features a highly advanced DOM synchronization engine. It handles complex rich-text editors like **Lexical (ChatGPT)** and **ProseMirror (Claude)** flawlessly. Using optimized `insertHTML` injection, it redacts text natively without corrupting the editor's internal state, dropping code block schema, or creating bizarre line spacing.

### 4. Negation-Aware Intent Classification
Traditional detectors trigger false alarms if you ask an AI to *"remove this credentials block."* PasteGuard uses a **negation-aware intent keyword matching engine** to dynamically adjust the threat level:
- **Risk Escalation (x 1.4):** Triggered when user intent is to keep or preserve secrets (e.g., *"keep as-is"*, *"don't change the key"*).
- **Risk Mitigation (x 0.5):** Triggered when the user intends to sanitize or clean up text (e.g., *"redact this before explaining"*).
- **Negation Filtering:** If risk-reducing keywords are preceded by negations (e.g. *"do not remove the secret"*), the discount is cancelled.

### 5. Rigorous False Positive Prevention (Hard Negatives)
PasteGuard's ML model is explicitly trained on a dedicated **Hard Negatives Dataset** containing prompts that discuss security concepts without actually leaking them (e.g., *"Write a tutorial explaining how SSH keys work"*). This guarantees high utility and zero workflow disruptions for developers.

---

## Detection Coverage

| Category | What is Blocked |
|---|---|
| **Cryptographic** | SSH / RSA / EC / PGP / OpenSSH private keys |
| **Cloud Credentials** | AWS, Stripe, GitHub, Slack, SendGrid, Twilio keys; JWT & Bearer tokens |
| **Database Credentials** | `postgres://`, `mysql://`, `mongodb://` connection strings; JDBC URLs; `DB_PASSWORD` variables |
| **Credentials** | Password assignments; username + password pairs; HTTP Basic Auth headers |
| **PII** | US Social Security Numbers; credit card numbers; email addresses; phone numbers |
| **Environment Secrets** | `.env`-style secret variable assignments and high-entropy standalone tokens |
| **Semantic Leaks** (ML only) | Proprietary business roadmaps, salary structures, or product designs without raw credentials |

---

## Architecture

```
                                      +------------------------------------+
                                      |          Web Page Input            |
                                      +------------------------------------+
                                                         |
                                                         v
                                      +------------------------------------+
                                      | MutationObserver & Debounced Scan  |
                                      +------------------------------------+
                                                         |
                                                         v
                                      +------------------------------------+
                                      |    detectInTextAll (content.js)    |
                                      +------------------------------------+
                                           /                          \
                                          v                            v
                      +--------------------------+      +--------------------------+
                      |       Regex Engine       |      |    Local ML Classifier   |
                      |  (Checks strict pattern  |      |  (TF-IDF + LogReg on     |
                      |   matches in the text)   |      |   exported weights JSON) |
                      +--------------------------+      +--------------------------+
                                          \                            /
                                           \                          /
                                            v                        v
                                      +------------------------------------+
                                      |  Scoring + Negation Intent Adjust  |
                                      +------------------------------------+
                                                         |
                                          ┌──────────────┴──────────────┐
                                    (Score < 70)                  (Score >= 70)
                                          |                             |
                                          v                             v
                                 +-----------------+           +-----------------+
                                 |   Allow Send    |           |   BLOCK SEND    |
                                 +-----------------+           | (Lock Button,   |
                                                               |  Apply Shadow,  |
                                                               |  Show Toolbar)  |
                                                               +-----------------+
```

---

## Project Directory Structure

```
├── manifest.json       Extension manifest (MV3)
├── content.js          Core detection engine + browser-side ML predictor
├── banner.css          Injected styles (banner, toolbar, toast)
├── model_weights.json  Exported ML model parameters
├── background.js       Background worker (log storage initialisation)
├── dashboard.html      Extension popup UI
├── dashboard.js        Popup logic (renders the local detection log)
├── icons/              Extension icons
├── data/               Offline ML research pipeline
│   ├── *.json              Training / evaluation datasets
│   ├── *.py                Dataset trainers and exporters
│   └── classifier_model.joblib
└── README.md
```

---

## Getting Started

### Installation
1. Clone this repository to your local machine.
2. Open Chrome and navigate to `chrome://extensions`.
3. Toggle **Developer mode** on in the top-right corner.
4. Click **Load unpacked** in the top-left corner.
5. Select the cloned repository directory.

### Running Tests
PasteGuard is built for rigorous testing! Feel free to copy highly sensitive AWS keys, proprietary data prompts, or credentials into ChatGPT or Claude to watch the real-time blocking, alerting, and auto-redaction in action.

---

## ML Pipeline Development (For Researchers)

If you wish to modify or retrain the machine learning model using the files in the `data/` directory:

```bash
# Create the environment & install dependencies
python -m venv .venv
.venv\Scripts\activate
pip install scikit-learn joblib
```

1. **Neutralize Raw Secrets:** Run `python data/neutralize_secrets.py` to strip any accidentally added real credentials before committing.
2. **Prepare Dataset:** Run `python data/prepare_dataset.py` to perform a stratified 70/30 train/test split.
3. **Train Classifier:** Run `python data/train_classifier.py` to train the TF-IDF and Logistic Regression pipeline, validate with Stratified 5-Fold Cross-Validation, and dump the `.joblib` model.
4. **Export Weights:** Run `python data/export_model_json.py` to convert the `.joblib` into the compact `model_weights.json` used by the extension.
