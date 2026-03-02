import joblib
from xgboost import XGBClassifier
from sklearn.calibration import CalibratedClassifierCV
from sklearn.model_selection import train_test_split
import pandas as pd
data = pd.read_csv("data/dataset_phishing.csv", encoding="latin1")
FEATURES = [
    "length_url", "length_hostname", "nb_subdomains",
    "ip", "prefix_suffix", "random_domain", "punycode", "port",
    "nb_dots", "nb_hyphens", "nb_at", "nb_qm", "nb_and", "nb_or",
    "nb_eq", "nb_underscore", "nb_tilde", "nb_percent", "nb_slash",
    "nb_star", "nb_colon", "nb_comma", "nb_semicolumn", "nb_dollar",
    "nb_space", "nb_dslash",
    "nb_www", "nb_com", "http_in_path", "https_token",
    "ratio_digits_url", "ratio_digits_host",
    "tld_in_path", "tld_in_subdomain", "abnormal_subdomain", "suspecious_tld",
    "shortening_service", "nb_redirection",
    "path_extension",
    "length_words_raw", "shortest_words_raw", "shortest_word_host",
    "shortest_word_path", "longest_words_raw", "longest_word_host",
    "longest_word_path", "avg_words_raw", "avg_word_host", "avg_word_path",
    "phish_hints"
]
X = data[FEATURES]
y = data["status"].map({"legitimate": 0, "phishing": 1})
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)
xgb_model = XGBClassifier(
    n_estimators=300,
    max_depth=4,
    learning_rate=0.05,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    random_state=42
)
xgb_model.fit(X_train, y_train)
calibrated_xgb = CalibratedClassifierCV(
    estimator=xgb_model,
    method="isotonic",
    cv=5
)
calibrated_xgb.fit(X_train, y_train)
joblib.dump(calibrated_xgb, "xgb_phishing_model.pkl")
print("✅ URL phishing model saved as xgb_phishing_model.pkl")