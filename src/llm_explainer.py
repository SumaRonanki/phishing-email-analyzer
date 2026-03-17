"""
LLM-Powered Phishing Email Analyzer - AI Explanation Layer
--------------------------------------------------------
Generates human-readable security analysis using GPT-3.5 or fallback heuristics.
"""
import os
import requests
import json
from typing import List, Dict, Any

def explain_phishing(email_text, prediction, probability, threat_score, indicators):
    """
    Apply AI-driven explanation logic to the classification results.
    """
    api_key = os.getenv("OPENAI_API_KEY")
    
    # Pre-process flags from indicators
    top_flags: List[str] = get_top_flags(indicators, threat_score)
    severity = calculate_severity(threat_score)
    
    if api_key:
        try:
            return call_llm_explainer(email_text, prediction, probability, threat_score, top_flags, severity, api_key)
        except Exception as e:
            print(f"Exception during LLM call: {e}. Reverting to fallback.")
            
    # Fallback path
    return fallback_explanation(email_text, prediction, probability, threat_score, top_flags, severity)

def get_top_flags(indicators, score):
    """
    Extract the top 3 most relevant red flags based on technical indicators.
    """
    flags = []
    
    if indicators.get('url_count', 0) > 0:
        flags.append(f"Contains {indicators['url_count']} suspicious URL(s)")
        
    if indicators.get('has_credential', 0):
        flags.append("Requests sensitive credentials or login information")
        
    if indicators.get('has_urgent', 0):
        flags.append("Uses urgent or coercive language to force quick action")
        
    if indicators.get('has_financial', 0):
        flags.append("Mentions financial transactions, invoices, or payments")
        
    if indicators.get('exclamation_count', 0) > 3:
        flags.append("Uses excessive exclamation marks often seen in spam")
        
    # Return top 3 as a simple list
    subset = []
    for i in range(min(len(flags), 3)):
        subset.append(flags[i])
    return subset
    
def calculate_severity(score):
    """
    Map threat score to a severity level.
    """
    if score >= 70:
        return "CRITICAL"
    elif score >= 40:
        return "WARNING"
    else:
        return "LOW"

def fallback_explanation(email_text, prediction, probability, threat_score, top_flags, severity):
    """
    Provide a template-based explanation when the LLM is unavailable.
    Returns the required dictionary structure.
    """
    if prediction == "Phishing":
        base_narrative = f"This email has been classified as PHISHING with a {probability:.1%} confidence level. "
        if top_flags:
            narrative = base_narrative + "The analysis identified several concerning elements, primarily " + ", ".join([f.lower() for f in top_flags]) + "."
        else:
            narrative = base_narrative + "The machine learning model detected structural or linguistic patterns commonly associated with malicious emails."
            
        analyst_summary = f"High probability of malicious intent (Score: {threat_score}/100). Do not interact with links or attachments. Recommend immediate block/quarantine." if threat_score >= 70 else f"Moderate probability of malicious intent (Score: {threat_score}/100). Exercise caution and verify sender identity out-of-band."
        
    else:
        narrative = f"This email has been classified as LEGITIMATE. The system found no strong indicators of phishing, returning a low threat score of {threat_score}/100."
        analyst_summary = "Email appears benign based on current heuristics and ML evaluation. Standard organizational security policies apply."
        
    return {
        "explanation": narrative,
        "top_flags": top_flags if top_flags else ["No major flags detected"],
        "severity": severity,
        "analyst_summary": analyst_summary
    }

def call_llm_explainer(email_text, prediction, probability, score, flags, severity, api_key):
    """
    Calls the OpenAI API to generate a professional cyber analyst summary.
    """
    prompt = f"""
    You are a tier-3 SOC analyst evaluating an email.
    
    Context:
    - ML Prediction: {prediction} ({probability:.1%} confidence)
    - Threat Score: {score}/100 (Severity: {severity})
    - Technical Flags Detected: {', '.join(flags) if flags else 'None'}
    
    Email Content:
    {email_text.replace('"""', "'''")}
    
    Provide your analysis in the following strict JSON format:
    {{
      "explanation": "2-3 sentences explaining exactly why this email is suspicious or safe, referencing specific details from the text.",
      "analyst_summary": "1 sentence executive summary with recommended action (e.g. Quarantine, Safe, Investigate further)"
    }}
    
    Keep the tone highly professional, objective, and concise. Do not use markdown backticks in your output, just return the raw JSON.
    """
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    data = {
        "model": "gpt-3.5-turbo",
        "messages": [{"role": "system", "content": "You are a cybersecurity expert. Return ONLY valid JSON."},
                     {"role": "user", "content": prompt}],
        "temperature": 0.2
    }
    
    response = requests.post("https://api.openai.com/v1/chat/completions", headers=headers, json=data, timeout=15)
    
    if response.status_code == 200:
        import json
        result = response.json()
        content = result["choices"][0]["message"]["content"].strip()
        
        # Super basic cleanup just in case the LLM wrapped it in markdown
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
            
        parsed = json.loads(content.strip())
        
        return {
            "explanation": parsed.get("explanation", "Error parsing explanation from LLM."),
            "top_flags": flags if flags else ["No major flags detected"],
            "severity": severity,
            "analyst_summary": parsed.get("analyst_summary", "Error parsing summary from LLM.")
        }
    else:
        print(f"LLM API Error: {response.status_code}")
        # Fallback if API fails but we have the key
        return fallback_explanation(email_text, prediction, probability, score, flags, severity)

if __name__ == "__main__":
    # Test the fallback
    sample_text = "URGENT: Your account has been compromised. Please login here immediately: http://fake-login.com"
    dummy_indicators = {'url_count': 1, 'has_urgent': 1, 'has_credential': 1, 'exclamation_count': 0, 'has_financial': 0}
    
    print("Testing Fallback Explainer:")
    res = explain_phishing(sample_text, "Phishing", 0.95, 85, dummy_indicators)
    
    print(f"Severity: {res['severity']}")
    print(f"Top Flags: {res['top_flags']}")
    print(f"Explanation: {res['explanation']}")
    print(f"Analyst Summary: {res['analyst_summary']}")
