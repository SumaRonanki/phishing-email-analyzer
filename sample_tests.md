# 🧪 Phishing Analyzer Test Cases

Use these samples to test the **LLM-Powered Phishing Analyzer** Streamlit app. Each case is designed to trigger specific parts of the ML model and rule-based scoring logic.

---

## ✅ Legitimate Emails (Expected: LOW Severity)

### 1. Internal Project Update
*   **Text:**
    ```text
    Hi Team, 
    
    I've uploaded the updated project roadmap for Q3 to the shared SharePoint folder. Please take a look at the new deadlines for the 'Cloud Migration' phase and let me know if you have any capacity concerns by EOD Wednesday. 
    
    Best, 
    Sarah
    ```
*   **Expected Prediction:** Legitimate
*   **Expected Red Flags:** None / "No major flags detected"
*   **Expected Severity:** LOW (Score: ~0-15)

### 2. Standard Meeting Invitation
*   **Text:**
    ```text
    Subject: Re: Weekly Sync - Marketing Strategy
    
    Hi everyone, 
    
    Are we still on for our 2 PM sync today? I have a few updates on the ad campaign performance data from last week that I'd like to share. I've attached the PDF summary to this invite.
    
    See you then,
    Mark
    ```
*   **Expected Prediction:** Legitimate
*   **Expected Red Flags:** None
*   **Expected Severity:** LOW (Score: ~0-20)

### 3. Service Status Notification
*   **Text:**
    ```text
    Scheduled Maintenance Notification: 
    
    Our internal HR portal will be offline for scheduled database maintenance this Saturday, March 14th, from 12:00 AM to 4:00 AM EST. No action is required on your part. We apologize for any inconvenience.
    
    - IT Operations Team
    ```
*   **Expected Prediction:** Legitimate
*   **Expected Red Flags:** None
*   **Expected Severity:** LOW (Score: ~0-10)

---

## 🚩 Phishing Emails (Expected: MEDIUM/HIGH Severity)

### 4. Direct Credential Harvesting (Aggressive)
*   **Text:**
    ```text
    URGENT: Your Outlook account has been compromised from an unknown IP address in Eastern Europe. For your protection, we have temporarily locked your account. 
    
    To restore access and verify your identity, you must login here immediately: http://outlook-secure-verify.com/login. Failure to act within 24 hours will result in permanent account suspension!!
    ```
*   **Expected Prediction:** Phishing
*   **Expected Red Flags:**
    - Contains suspicious URL(s)
    - Requests sensitive credentials or login information
    - Uses urgent or coercive language to force quick action
*   **Expected Severity:** CRITICAL (Score: 85-100)

### 5. Fake Invoice / Financial Pressure
*   **Text:**
    ```text
    Your payment for Invoice #INV-98231-B is now OVERDUE. 
    
    A late fee of $150.00 has been applied to your balance. Please download the attached billing statement and process the wire transfer today to avoid further legal action and credit reporting.
    
    Billing Department,
    Global Logistics Corp
    ```
*   **Expected Prediction:** Phishing
*   **Expected Red Flags:**
    - Mentions financial transactions, invoices, or payments
    - Uses urgent or coercive language to force quick action
*   **Expected Severity:** WARNING / CRITICAL (Score: 65-80)

### 6. "Service Update" Phishing (Subtle)
*   **Text:**
    ```text
    Action Required: New security policy update for all employees. 
    
    As part of our commitment to data safety, we require all staff to re-enroll in our Multi-Factor Authentication (MFA) portal by the end of the week. Please visit the internal security site at http://company-mfa-enrollment.net/update to complete your profile.
    ```
*   **Expected Prediction:** Phishing
*   **Expected Red Flags:**
    - Contains suspicious URL(s)
    - Requests sensitive credentials or login information
*   **Expected Severity:** WARNING (Score: 50-70)
