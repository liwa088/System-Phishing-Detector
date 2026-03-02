# Extractor.py
import re
import os
import pandas as pd
from urllib.parse import urlparse
import tldextract

SHORTENING_SERVICES = [
    "bit.ly", "goo.gl", "tinyurl", "ow.ly", "t.co", "is.gd", "buff.ly"
]

SUSPICIOUS_TLDS = ["tk", "ml", "ga", "cf", "gq"]

FEATURE_ORDER = [
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

def extract_url_features(url):
    f = {}

    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    ext = tldextract.extract(url)
    hostname = ext.domain + "." + ext.suffix if ext.suffix else ext.domain

    # --- Length & structure ---
    f["length_url"] = len(url)
    f["length_hostname"] = len(hostname)
    f["nb_subdomains"] = len(ext.subdomain.split(".")) if ext.subdomain else 0

    # --- IP / domain ---
    f["ip"] = int(bool(re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", domain)))
    f["prefix_suffix"] = int("-" in hostname)
    f["random_domain"] = int(bool(re.search(r"[a-z]{10,}", ext.domain)))
    f["punycode"] = int(domain.startswith("xn--"))
    f["port"] = int(parsed.port is not None)

    # --- Characters ---
    for k, v in {
        "nb_dots": ".", "nb_hyphens": "-", "nb_at": "@", "nb_qm": "?",
        "nb_and": "&", "nb_or": "or", "nb_eq": "=", "nb_underscore": "_",
        "nb_tilde": "~", "nb_percent": "%", "nb_slash": "/", "nb_star": "*",
        "nb_colon": ":", "nb_comma": ",", "nb_semicolumn": ";",
        "nb_dollar": "$", "nb_space": " ", "nb_dslash": "//"
    }.items():
        f[k] = url.lower().count(v)

    # --- Tokens ---
    f["nb_www"] = domain.count("www")
    f["nb_com"] = domain.count("com")
    f["http_in_path"] = int("http" in path)
    f["https_token"] = int("https" in url and not url.startswith("https"))

    # --- Ratios ---
    f["ratio_digits_url"] = sum(c.isdigit() for c in url) / len(url)
    f["ratio_digits_host"] = (
        sum(c.isdigit() for c in hostname) / len(hostname)
        if hostname else 0
    )

    # --- TLD tricks ---
    f["tld_in_path"] = int(ext.suffix in path)
    f["tld_in_subdomain"] = int(ext.suffix in ext.subdomain)
    f["abnormal_subdomain"] = int(ext.subdomain.count(".") > 2)
    f["suspecious_tld"] = int(ext.suffix in SUSPICIOUS_TLDS)

    # --- Redirection & shortening ---
    f["shortening_service"] = int(any(s in domain for s in SHORTENING_SERVICES))
    f["nb_redirection"] = url.count("://") - 1

    # --- Path ---
    f["path_extension"] = int(os.path.splitext(path)[1] != "")

    # --- Words ---
    words = re.split(r"\W+", url)
    host_words = re.split(r"\W+", hostname)
    path_words = re.split(r"\W+", path)

    f["length_words_raw"] = sum(len(w) for w in words if w)
    f["shortest_words_raw"] = min((len(w) for w in words if w), default=0)
    f["shortest_word_host"] = min((len(w) for w in host_words if w), default=0)
    f["shortest_word_path"] = min((len(w) for w in path_words if w), default=0)
    f["longest_words_raw"] = max((len(w) for w in words if w), default=0)
    f["longest_word_host"] = max((len(w) for w in host_words if w), default=0)
    f["longest_word_path"] = max((len(w) for w in path_words if w), default=0)

    valid_words = [w for w in words if w]
    f["avg_words_raw"] = (
        sum(len(w) for w in valid_words) / len(valid_words)
        if len(valid_words) > 0 else 0
    )

    valid_host_words = [w for w in host_words if w]
    f["avg_word_host"] = (
        sum(len(w) for w in valid_host_words) / len(valid_host_words)
        if len(valid_host_words) > 0 else 0
    )
    
    valid_path_words = [w for w in path_words if w]

    f["avg_word_path"] = (
        sum(len(w) for w in valid_path_words) / len(valid_path_words)
        if len(valid_path_words) > 0 else 0
    )

    # --- Phishing hints ---
    PHISH_HINTS = ["login", "secure", "account", "verify", "update", "bank"]
    f["phish_hints"] = sum(h in url.lower() for h in PHISH_HINTS)

    #  RETURN ORDERED DATAFRAME
    return pd.DataFrame([[f[col] for col in FEATURE_ORDER]], columns=FEATURE_ORDER)
