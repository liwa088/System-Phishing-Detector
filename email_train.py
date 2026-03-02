import pandas as pd
import numpy as np
import re
import matplotlib.pyplot as plt
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.svm import LinearSVC
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, recall_score, f1_score
from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
from scipy.sparse import hstack
df = pd.read_csv("data/emails.csv")
df.dropna(inplace=True)
df["text"] = df["subject"] + " " + df["body"]
def clean_text(text):
    text = text.lower()
    text = re.sub(r"http\S+", "", text)
    text = re.sub(r"[^a-z\s]", "", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()
df["text"] = df["text"].apply(clean_text)
vectorizer = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1, 2),
    stop_words="english"
)
X_text = vectorizer.fit_transform(df["text"])
df["urls"] = df["urls"].astype(int)
X_url = df[["urls"]].values
X = hstack([X_text, X_url])
y = df["label"]
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42
)
models = {
    "Logistic Regression": LogisticRegression(max_iter=1000),
    "Linear SVM": LinearSVC(),
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42)
}
metrics = {}
trained_models = {}
for name, model in models.items():
    model.fit(X_train, y_train)
    y_pred = model.predict(X_test)
    metrics[name] = {
        "accuracy": accuracy_score(y_test, y_pred),
        "recall": recall_score(y_test, y_pred),
        "f1": f1_score(y_test, y_pred)
    }
    trained_models[name] = model
    print(f"\n{name}")
    print(metrics[name])
final_model = trained_models["Logistic Regression"]
joblib.dump(final_model, "phishing_model.pkl")
joblib.dump(vectorizer, "tfidf_vectorizer.pkl")
print("\nModel and vectorizer saved.")