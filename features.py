"""
LLM-Powered Phishing Email Analyzer - Feature Engineering Module
--------------------------------------------------------------
Provides automated extraction of linguistic and technical indicators.
"""
import pandas as pd
import re

def extract_engineering_features(text):
    """
    Extract phishing-specific features from a single email text string.
    
    Args:
        text (str): The raw email content.
        
    Returns:
        dict: A dictionary of numerical and categorical phishing indicators.
    """
    if not isinstance(text, str):
        text = str(text)

    # 1. Total text length
    text_length = len(text)
    
    # 2. URL count (handles raw URLs or <URL> tokens from preprocessing)
    url_pattern = re.compile(r'https?://[^\s]+|www\.[^\s]+|<url>', re.IGNORECASE)
    url_count = len(url_pattern.findall(text))
    
    # 3. Exclamation count
    exclamation_count = text.count('!')
    
    # 4. Digit count
    digit_count = sum(c.isdigit() for c in text)
    
    # 5. Uppercase ratio
    uppercase_count = sum(c.isupper() for c in text)
    total_letters = sum(c.isalpha() for c in text)
    uppercase_ratio = uppercase_count / total_letters if total_letters > 0 else 0.0
    
    # 6. Urgent keyword flag
    urgent_words = [
        'urgent', 'immediate', 'action required', 'alert', 
        'important', 'warning', 'suspension', 'act now'
    ]
    text_lower = text.lower()
    has_urgent = int(any(word in text_lower for word in urgent_words))
    
    # 7. Credential-request keyword flag
    credential_words = [
        'password', 'login', 'account', 'verify', 
        'update', 'ssn', 'social security'
    ]
    has_credential = int(any(word in text_lower for word in credential_words))
    
    # 8. Financial-pressure keyword flag
    financial_words = [
        'bank', 'credit card', 'payment', 'invoice', 
        'billing', 'transaction', 'wire transfer', 'funds'
    ]
    has_financial = int(any(word in text_lower for word in financial_words))
    
    return {
        'url_count': url_count,
        'exclamation_count': exclamation_count,
        'digit_count': digit_count,
        'uppercase_ratio': uppercase_ratio,
        'text_length': text_length,
        'has_urgent': has_urgent,
        'has_credential': has_credential,
        'has_financial': has_financial
    }

def generate_features(df, text_column='text'):
    """
    Apply feature engineering to the entire dataframe.
    
    Args:
        df (pd.DataFrame): The input dataframe containing email texts.
        text_column (str): The name of the column containing the email text.
        
    Returns:
        pd.DataFrame: A dataframe containing ONLY the engineered features,
                      which can easily be horizontally stacked with a TF-IDF matrix.
    """
    print("Generating structural and keyword-based features...")
    
    # Extract features for each row into a list of dictionaries
    features_list = df[text_column].apply(extract_engineering_features)
    
    # Convert lists of dictionaries to a Pandas DataFrame
    features_df = pd.DataFrame(features_list.tolist(), index=df.index)
    
    print("Feature generation complete!")
    return features_df

if __name__ == "__main__":
    # Small test logic if the script is run directly
    sample_data = pd.DataFrame({
        'text': ["URGENT! Please verify your bank account details at http://fake.com NOW!!",
                 "Hi team, just a reminder about the meeting tomorrow."]
    })
    
    df_features = generate_features(sample_data, 'text')
    print("\\nSample Features Output:")
    print(df_features)
