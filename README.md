# LLM-Powered Phishing Email Analyzer

An end-to-end Machine Learning and AI pipeline designed to detect, score, and explain phishing attempts with **98.3% accuracy**. This project combines traditional Natural Language Processing (NLP) with a human-centric LLM explanation layer to bridge the gap between "black-box" model predictions and actionable security intelligence.

---

## Project Overview
Phishing remains the #1 initial entry vector for cyber-attacks worldwide. This project provides a full-stack solution that:
1.  **Classifies** emails as "Phishing" or "Legitimate" using a hybrid ML model.
2.  **Quantifies** risk via a transparent 0-100 Threat Scoring engine.
3.  **Explains** findings using an LLM (GPT-3.5) to provide professional, SOC-analyst style summaries.

## Dataset & Features
- **Source:** Combined dataset of ~82,000 emails (Phishing vs. Benign).
- **Preprocessing:** Automated cleaning pipeline that handles HTML stripping, URL/Email tokenization, and whitespace normalization.
- **Hybrid Feature Engineering:**
    - **TF-IDF Vectorization:** Captures 5,000 linguistic patterns and N-grams.
    - **Standardized Structural Indicators:** Custom logic to detect urgent language, credential harvesting hooks, financial pressure keywords, and suspicious URL counts, all normalized via **StandardScaler**.

## Technical Architecture

### Model Training
The project implements a comparison suite between **Logistic Regression** and **Multinomial Naive Bayes**. The current production model leverages **Logistic Regression** due to its superior F1-score and robustness.
- **Accuracy:** 98.3%
- **Precision:** 98.0%
- **Recall:** 98.8%

### Threat Scoring Engine
A transparent logic layer calculates a **0-100 Risk Score** based on:
- **Model Confidence (50%):** Weighted probability from the ML classifier.
- **Technical Indicators (50%):** Hard-coded points for high-risk elements (Urgent language, suspicious URLs, credential requests).
- **Severity Bands:** *Low (0-39)*, *Medium (40-69)*, *High (70-100)*.

### LLM Explanation Layer
To make the tool useful for non-technical users, an **LLM Explainer** (Powered by OpenAI) generates:
- **Narrative Explanation:** 2-3 sentences explaining exactly why the email is suspicious.
- **Top 3 Red Flags:** The most critical indicators found in the text.
- **Analyst Summary:** A one-sentence recommendation (e.g., *"Immediate Quarantine Recommended"*).
- *Fallback Mechanism:* If no API key is present, the system uses a deterministic template engine to maintain functionality.

---

## Project Structure
```text
llm-phishing-analyzer/
├── app/
│   └── streamlit_app.py      # Interactive Web UI
├── data/
│   ├── raw/                  # Initial raw email datasets
│   └── processed/            # Cleaned data for training
├── models/
│   ├── best_model.pkl        # Trained Logistic Regression model
│   ├── scaler.pkl            # Standard scaler for structural features
│   └── tfidf_vectorizer.pkl  # Saved NLP vectorizer
├── src/
│   ├── preprocess.py         # Data cleaning logic
│   ├── train.py              # Training & Evaluation script
│   ├── features.py           # Feature engineering logic
│   ├── predict.py            # Inference & Scoring pipeline
│   └── llm_explainer.py      # AI-generated analysis layer
├── requirements.txt          # Python dependencies
└── README.md                 # Project documentation
```

---

## Setup & Usage

### 1. Installation
```powershell
# Clone the repository
git clone https://github.com/your-username/llm-phishing-analyzer.git
cd llm-phishing-analyzer

# Install dependencies
pip install -r requirements.txt
```

### 2. Run the Full Pipeline
You can run each stage of the life-cycle directly:

```powershell
# Preprocess the raw data
python src/preprocess.py

# Train the model (generates artifacts in /models)
python src/train.py

# Launch the interactive Dashboard
streamlit run app/streamlit_app.py
```

### 3. (Optional) Enable LLM Analysis
Create an `.env` file or set your environment variable:
`$env:OPENAI_API_KEY = "your-key-here"`

---

## Interview Preparation (Cheat Sheet)
If you're presenting this project in an interview, be prepared to discuss these core concepts:

1. **The Cold Start Problem:** How do you handle emails with no historical data? 
   * *Answer:* We use **Hybrid Features**. Even if the TF-IDF doesn't recognize the words, our manual heuristics catch "Urgent" keywords and link counts.
2. **False Positives vs. False Negatives:** Which is more dangerous in phishing?
   * *Answer:* A **False Negative** (missing a phish) leads to a breach, while a **False Positive** (blocking a real email) is a productivity nuisance. We prioritize high **Recall** for phishing to ensure threat capture.
3. **LLM Explainability:** Why use an LLM instead of just showing the ML score?
   * *Answer:* Security analysts need "Why", not just "What". The LLM translates abstract feature weights into human-readable flags that speed up incident response.
4. **Data Leakage:** How did you ensure your model wasn't "cheating"?
   * *Answer:* We cleaned the text by stripping unique identifiers and tokenizing URLs/Emails (`<URL>`, `<EMAIL>`) so the model learns patterns, not specific known-bad addresses.

---

## Resume-Ready Highlights
- **Engineered a hybrid phishing detection pipeline** achieving **98.3% accuracy** on a dataset of 80k+ emails by combining TF-IDF vectorization with standardized structural cybersecurity indicator extraction.
- **Developed a transparent 0-100 Threat Scoring engine** that maps model probability and technical indicators to human-readable severity bands (Low, Medium, High).
- **Integrated an LLM-based explanation layer** using the OpenAI API to translate complex ML features into professional SOC analyst summaries and actionable red flags.

## Future Improvements
- [ ] Integration with real-world email APIs (IMAP/Outlook).
- [ ] Support for deep learning models (LSTMs/Transformers).
- [ ] Multi-language support for international phishing campaigns.
