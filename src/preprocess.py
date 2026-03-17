"""
LLM-Powered Phishing Email Analyzer - Data Preprocessing
------------------------------------------------------
Initial cleaning and normalization of raw email datasets.
"""
import pandas as pd
import re
import os

def clean_text(text):
    """
    Clean the email text by applying standard preprocessing steps while preserving 
    suspicious patterns (like excessive punctuation or specific keywords).
    """
    if not isinstance(text, str):
        text = str(text)
        
    # 1. Strip HTML if present
    text = re.sub(r'<[^>]+>', ' ', text)
    
    # 2. Replace URLs with a URL token
    text = re.sub(r'https?://\S+|www\.\S+', '<URL>', text)
    
    # 3. Replace email addresses with an EMAIL token
    text = re.sub(r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b', '<EMAIL>', text)
    
    # 4. Remove extra whitespace (newlines, tabs, spaces)
    text = re.sub(r'\s+', ' ', text).strip()
    
    return text

def preprocess_dataset(input_path='data/raw/phishing_email.csv', output_path='data/processed/processed_emails.csv'):
    """
    Load raw dataset, apply cleaning, and save to a processed file.
    """
    print(f"Loading raw dataset from {input_path}...")
    try:
        df = pd.read_csv(input_path)
    except FileNotFoundError:
        print(f"Error: The dataset {input_path} does not exist.")
        return

    # Select proper columns based on our dataset mapping
    text_col = 'text_combined' if 'text_combined' in df.columns else 'text'
    label_col = 'label'
    
    if text_col not in df.columns or label_col not in df.columns:
        print(f"Error: Missing expected columns. Available features: {df.columns.tolist()}")
        return
        
    # Only keep our target text and label columns mapping the text to standard 'text'
    df = df[[text_col, label_col]].copy()
    df.rename(columns={text_col: 'text'}, inplace=True)
    
    print("Cleaning email text (this might take a few seconds)...")
    # Apply the cleaning sequence
    df['text'] = df['text'].apply(clean_text)
    
    # Ensure processed directory is present
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    print(f"Saving processed dataframe to {output_path}...")
    df.to_csv(output_path, index=False)
    
    print("Done! Here's a quick preview:")
    print(df.head())

if __name__ == "__main__":
    # Ensure working directory consistency
    preprocess_dataset()
