# Phishing Detection System (URL + Email)

![Python](https://img.shields.io/badge/Python-3.9+-blue)
![Machine Learning](https://img.shields.io/badge/Machine%20Learning-Scikit--Learn-orange)
![Interface](https://img.shields.io/badge/Interface-Gradio-green)
![Deployment](https://img.shields.io/badge/Deployment-HuggingFace-yellow)
![Status](https://img.shields.io/badge/Project-Active-brightgreen)

A **Machine Learning-based phishing detection system** capable of identifying **phishing URLs and phishing emails**.  
The system analyzes suspicious patterns in both **web links and email text** to determine whether the content is **malicious or legitimate**.

The application is deployed using **Gradio** and hosted on **Hugging Face Spaces** for interactive testing.

---

# Live Demo

Try the system online:

**Hugging Face Demo**

https://huggingface.co/spaces/Liwa08/System_Phishing_Detector

Users can test the system by entering:

- a **URL** to check if it is phishing  
- an **email message** to detect phishing attempts  

---

# Project Overview

Phishing attacks are among the most common cybersecurity threats. Attackers often use:

- malicious links
- fake login pages
- deceptive emails

to steal sensitive information such as:

- passwords
- banking credentials
- personal data

This project builds a **machine learning system that detects phishing attempts from both URLs and emails**.

---

# System Capabilities

The system includes two detection modules:

### URL Phishing Detection
Analyzes suspicious characteristics of URLs such as:

- domain patterns
- unusual tokens
- special characters
- URL length
- suspicious keywords

### Email Phishing Detection
Analyzes email text using **Natural Language Processing (NLP)** techniques to detect:

- suspicious wording
- phishing language patterns
- malicious intent

---

# Features

- Phishing **URL detection**
- Phishing **email detection**
- Feature extraction from URLs
- NLP processing for email analysis
- Multiple machine learning models
- Interactive **Gradio interface**
- Cloud deployment using **Hugging Face Spaces**

---

# Technologies Used

## Programming Language
- Python

## Libraries
- scikit-learn
- pandas
- numpy
- matplotlib
- tldextract
- joblib
- gradio

---

# Machine Learning Models

The system uses different models trained for phishing detection:

| Model | Purpose |
|------|------|
| Logistic Regression | Baseline classifier |
| Linear SVM | High-dimensional text classification |
| Random Forest | Ensemble learning |
| XGBoost | High-performance boosting model |

---
