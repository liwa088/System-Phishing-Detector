import gradio as gr
import joblib
import re
import numpy as np
from scipy.sparse import hstack
from Extractor import extract_url_features
email_model = joblib.load("phishing_model.pkl")
vectorizer = joblib.load("tfidf_vectorizer.pkl")
url_model = joblib.load("xgb_phishing_model.pkl")
EMAIL_THRESHOLD = 0.5
URL_THRESHOLD = 0.8
def clean_text(text):
    text = text.lower()
    text = re.sub(r"http\S+", " url ", text)
    text = re.sub(r"[^a-z\s]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()
def extract_urls(text):
    return re.findall(r"https?://[^\s]+", text)
def predict_email(subject, body):
    if not subject.strip() and not body.strip():
        return "⚠️ Please enter email subject or body."
    full_text = subject + " " + body
    cleaned = clean_text(full_text)
    text_vec = vectorizer.transform([cleaned])
    url_present = 1 if re.search(r"http|www", body.lower()) else 0
    url_vec = np.array([[url_present]])
    X = hstack([text_vec, url_vec])
    pred = email_model.predict(X)[0]
    urls = extract_urls(body)
    url_results = []
    for url in urls:
        features = extract_url_features(url)
        prob = url_model.predict_proba(features)[0][1]
        label = "🚨 Phishing URL" if prob >= URL_THRESHOLD else "✅ Safe URL"
        url_results.append(f"{label} ({prob:.2%})\n{url}")
    result = "🚨 PHISHING EMAIL" if pred == 1 else "✅ SAFE EMAIL"
    if url_results:
        result += "\n\n🔗 URL Analysis:\n" + "\n\n".join(url_results)
    return result
def predict_url_only(url):
    if not url.strip():
        return "⚠️ Please enter a URL."
    features = extract_url_features(url)
    prob = url_model.predict_proba(features)[0][1]
    if prob >= URL_THRESHOLD:
        return f"🚨 Phishing URL\nConfidence: {prob:.2%}"
    else:
        return f"✅ Safe URL\nConfidence: {(1 - prob):.2%}"
with gr.Blocks(title="Phishing Detection System") as app:
    gr.Markdown(
        """
        # 🛡️ Phishing Detection System
        Detect phishing using **Email Content Analysis** and **URL Structure Analysis**
        """
    )
    with gr.Tab("📧 Email Detection"):
        subject_input = gr.Textbox(label="Email Subject")
        body_input = gr.Textbox(label="Email Body", lines=10)
        email_output = gr.Textbox(label="Result", lines=10)
        email_btn = gr.Button("Analyze Email")
        email_btn.click(
            predict_email,
            inputs=[subject_input, body_input],
            outputs=email_output
        )
    with gr.Tab("🔗 URL Detection"):
        url_input = gr.Textbox(label="URL")
        url_output = gr.Textbox(label="Result")
        url_btn = gr.Button("Analyze URL")
        url_btn.click(
            predict_url_only,
            inputs=url_input,
            outputs=url_output
        )
if __name__ == "__main__":
    app.launch()
