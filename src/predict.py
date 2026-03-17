"""
LLM-Powered Phishing Email Analyzer - Inference Pipeline
------------------------------------------------------
Orchestrates model prediction, threat scoring, and result aggregation.
"""
import os
import sys

# Ensure the project root is in sys.path for direct script execution
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

try:
    import joblib
    import pandas as pd
    from scipy.sparse import hstack
    from src.features import generate_features, extract_engineering_features
    from src.preprocess import clean_text
except ImportError as e:
    print(f"CRITICAL ERROR: Missing dependency - {e}")
    sys.exit(1)

def load_models(model_dir='models'):
    """
    Load the trained model, TF-IDF vectorizer, and scaler (if exists).
    """
    model_path = os.path.join(model_dir, 'best_model.pkl')
    vectorizer_path = os.path.join(model_dir, 'tfidf_vectorizer.pkl')
    scaler_path = os.path.join(model_dir, 'scaler.pkl')
    
    if not os.path.exists(model_path) or not os.path.exists(vectorizer_path):
        raise FileNotFoundError(f"Missing models! Ensure {model_path} and {vectorizer_path} exist by running src/train.py first.")
        
    model = joblib.load(model_path)
    vectorizer = joblib.load(vectorizer_path)
    
    scaler = None
    if os.path.exists(scaler_path):
        scaler = joblib.load(scaler_path)
    
    return model, vectorizer, scaler

def calculate_threat_score(probability, indicators):
    """
    Calculates a threat score from 0 to 100 based on the model probability
    and specific phishing indicators.
    """
    score = 0.0
    
    # 1. Base Score from Model Probability (up to 50 points)
    # A model probability of 1.0 = 50 points
    score += (probability * 50)
    
    # 2. Suspicious URL Count (up to 20 points, 10 pts per URL)
    url_points = min(indicators.get('url_count', 0) * 10, 20)
    score += url_points
    
    # 3. Urgent Language (10 points)
    if indicators.get('has_urgent', 0):
        score += 10
        
    # 4. Credential Requests (10 points)
    if indicators.get('has_credential', 0):
        score += 10
        
    # 5. Financial Requests (10 points)
    if indicators.get('has_financial', 0):
        score += 10
        
    # Cap score at 100
    score = min(int(score), 100)
    
    # Determine Threat Band
    if score < 40:
        threat_band = "Low"
    elif score < 70:
        threat_band = "Medium"
    else:
        threat_band = "High"
        
    return score, threat_band

def predict_email(text, model_dir='models'):
    """
    Accepts raw email text, runs preprocessing and model prediction.
    Returns a dictionary with result details including:
    - predicted label
    - phishing probability
    - extracted phishing indicators
    - feature summary for scoring
    """
    model, vectorizer, scaler = load_models(model_dir)
    
    # Create DataFrame for compatibility with existing functions
    # Important: Apply the same cleaning as during training
    cleaned_text = clean_text(text)
    df = pd.DataFrame({'text': [cleaned_text]})
    
    # 1. TF-IDF features
    tfidf_features = vectorizer.transform(df['text'])
    
    # 2. Engineered features
    custom_features_df = generate_features(df, text_column='text')
    
    # 3. Apply Scaling if scaler exists
    if scaler:
        custom_features_vals = scaler.transform(custom_features_df)
    else:
        custom_features_vals = custom_features_df.values
    
    # 4. Combine them
    X_combined = hstack([tfidf_features, custom_features_vals])
    
    # 5. Predict
    prediction = model.predict(X_combined)[0]
    probabilities = model.predict_proba(X_combined)[0]
    
    # Determine probability of phishing (assuming 1 is Phishing, 0 is Legitimate)
    classes = list(model.classes_)
    if 1 in classes:
        phishing_index = classes.index(1)
    else:
        # Fallback if classes are named differently
        phishing_index = len(classes) - 1
        
    phishing_prob = probabilities[phishing_index]
    predicted_label = "Phishing" if prediction == 1 else "Legitimate"
    
    # 5. Extract phishing indicators / feature summary
    indicators = extract_engineering_features(text)
    
    # 6. Calculate threat score
    threat_score, threat_band = calculate_threat_score(float(phishing_prob), indicators)
    
    return {
        'label': predicted_label,
        'probability': float(phishing_prob),
        'threat_score': threat_score,
        'threat_band': threat_band,
        'indicators': indicators,
        'features_df': custom_features_df
    }

if __name__ == "__main__":
    sample_text = "URGENT: Your account has been compromised. Please login here immediately: http://fake-login.com to reset your password!!"
    try:
        results = predict_email(sample_text)
        print("Prediction:", results['label'])
        print(f"Phishing Probability: {results['probability']:.4f}")
        print(f"Threat Score: {results['threat_score']}/100 - {results['threat_band']}")
        print("Indicators:", results['indicators'])
    except Exception as e:
        print("Error testing predict_email:", e)
