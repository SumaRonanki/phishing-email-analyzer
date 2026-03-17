"""
LLM-Powered Phishing Email Analyzer - Training Module
---------------------------------------------------
Handles dataset loading, vectorization, model training, and evaluation.
"""
import os
import sys

# Ensure the project root is in sys.path for direct script execution
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    import pandas as pd
    import numpy as np
    import joblib
    import matplotlib.pyplot as plt
    import seaborn as sns
    from sklearn.model_selection import train_test_split
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.naive_bayes import MultinomialNB
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, 
        f1_score, confusion_matrix, classification_report
    )
    from sklearn.preprocessing import StandardScaler
    from scipy.sparse import hstack
    # Standard package-style import
    from src.features import generate_features
except ImportError as e:
    print(f"CRITICAL ERROR: Missing dependency - {e}")
    print("Please ensure all requirements are installed: pip install -r requirements.txt")
    sys.exit(1)

def evaluate_model(name, y_true, y_pred):
    """
    Print standard evaluation metrics for a model.
    """
    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred)
    rec = recall_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    
    print(f"--- {name} ---")
    print(f"Accuracy  : {acc:.4f}")
    print(f"Precision : {prec:.4f}")
    print(f"Recall    : {rec:.4f}")
    print(f"F1-Score  : {f1:.4f}")
    print("\nClassification Report:")
    print(classification_report(y_true, y_pred))
    
    return f1

def save_confusion_matrix(y_true, y_pred, model_name, path):
    """
    Generate and save a heatmap of the confusion matrix.
    """
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', 
                xticklabels=['Legitimate', 'Phishing'], 
                yticklabels=['Legitimate', 'Phishing'])
    plt.title(f'Confusion Matrix: {model_name}')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    plt.savefig(path)
    plt.close()
    print(f"Confusion matrix saved to {path}")

def train_models(data_path='data/processed/processed_emails.csv', model_dir='models'):
    """
    Train ML models with TF-IDF and engineered features, compare them, and save the best one.
    """
    # 1. Load data
    print(f"Loading data from {data_path}...")
    if not os.path.exists(data_path):
        print(f"Error: Could not find {data_path}. Please run src/preprocess.py first.")
        return

    df = pd.read_csv(data_path)
    df = df.dropna(subset=['text', 'label']) # safety check
    
    # 2. Extract structural features
    X_custom_df = generate_features(df, text_column='text')
    
    # 3. Split data
    print("Splitting train/test data...")
    X_train_text, X_test_text, X_train_cust, X_test_cust, y_train, y_test = train_test_split(
        df['text'], X_custom_df, df['label'], test_size=0.2, random_state=42
    )

    # 4. Feature Scaling for Engineered Features
    # Important: Scale engineered features so they don't overpower TF-IDF
    print("Scaling Engineered Features...")
    scaler = StandardScaler()
    X_train_cust_scaled = scaler.fit_transform(X_train_cust)
    X_test_cust_scaled = scaler.transform(X_test_cust)

    # 5. TF-IDF Vectorization
    print("Vectorizing Text (TF-IDF)...")
    vectorizer = TfidfVectorizer(max_features=5000)
    X_train_tfidf = vectorizer.fit_transform(X_train_text)
    X_test_tfidf = vectorizer.transform(X_test_text)

    # Combine TF-IDF features with our Engineered Features
    X_train_combined = hstack([X_train_tfidf, X_train_cust_scaled])
    X_test_combined = hstack([X_test_tfidf, X_test_cust_scaled])

    # 6. Train baseline: Logistic Regression
    print("\nTraining Baseline: Logistic Regression...")
    # Increase max_iter to ensure convergence with many features
    lr_model = LogisticRegression(max_iter=5000, random_state=42)
    lr_model.fit(X_train_combined, y_train)
    lr_preds = lr_model.predict(X_test_combined)
    lr_f1 = evaluate_model("Logistic Regression", y_test, lr_preds)

    # 7. Train comparison: Multinomial Naive Bayes (Requires non-negative features)
    # Note: Standardized features can be negative, but MNB is robust to some minor shifts.
    # However, conventionally, we might use MinMaxScaler for MNB if needed.
    # For now, let's see if MNB still performs well or if we focus on LR.
    print("\nTraining Comparison: Multinomial Naive Bayes...")
    # MNB doesn't play well with negative values from StandardScaler.
    # We'll use the unscaled custom features for MNB since it's a frequency-based model.
    X_train_combined_mnb = hstack([X_train_tfidf, X_train_cust.values])
    X_test_combined_mnb = hstack([X_test_tfidf, X_test_cust.values])
    
    nb_model = MultinomialNB()
    nb_model.fit(X_train_combined_mnb, y_train)
    nb_preds = nb_model.predict(X_test_combined_mnb)
    nb_f1 = evaluate_model("Multinomial Naive Bayes", y_test, nb_preds)

    # 8. Select the best model and export
    os.makedirs(model_dir, exist_ok=True)
    
    best_model = None
    best_preds = None
    best_name = ""
    
    if lr_f1 >= nb_f1:
        print("\nWinner: Logistic Regression! Saving model...")
        best_model = lr_model
        best_preds = lr_preds
        best_name = "Logistic_Regression"
        joblib.dump(lr_model, os.path.join(model_dir, 'best_model.pkl'))
        # Save scaler ONLY if LR wins (NB didn't use it)
        joblib.dump(scaler, os.path.join(model_dir, 'scaler.pkl'))
    else:
        print("\nWinner: Multinomial Naive Bayes! Saving model...")
        best_model = nb_model
        best_preds = nb_preds
        best_name = "Multinomial_Naive_Bayes"
        joblib.dump(nb_model, os.path.join(model_dir, 'best_model.pkl'))

    # Always save the vectorizer so the production app can transform text
    joblib.dump(vectorizer, os.path.join(model_dir, 'tfidf_vectorizer.pkl'))
    
    # Extract the confusion matrix of the best model
    cm_path = os.path.join(model_dir, 'confusion_matrix.png')
    save_confusion_matrix(y_test, best_preds, best_name, cm_path)

if __name__ == "__main__":
    # Ensure correct project paths regardless of where the script is called from
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    data_file = os.path.join(base_dir, 'data', 'processed', 'processed_emails.csv')
    model_folder = os.path.join(base_dir, 'models')
    
    # Ensure the models directory exists
    if not os.path.exists(model_folder):
        os.makedirs(model_folder)
        
    # Run training
    train_models(data_path=data_file, model_dir=model_folder)
