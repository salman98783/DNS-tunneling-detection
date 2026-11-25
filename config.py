"""
config.py - every setting and threshold used by the tool, in one place.

If the examiner asks "where did this number come from?", the answer is here,
with the reason written next to it.
"""
import os
import shutil

# ---------------------------------------------------------------------------
# Files and folders
# ---------------------------------------------------------------------------
PCAP_FOLDER = "data/pcaps"          # raw packet captures go here
SOURCES_FILE = "sources.csv"        # list of PCAPs + their label (the "manifest")
EXTRACTED_CSV = "data/1_extracted.csv"
CLEANED_CSV = "data/2_cleaned.csv"
FEATURES_CSV = "data/3_features.csv"
RESULTS_FOLDER = "results"


def find_tshark():
    """Find tshark (it is installed together with Wireshark)."""
    on_path = shutil.which("tshark")
    if on_path:
        return on_path
    windows_default = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(windows_default):
        return windows_default
    raise FileNotFoundError("tshark not found - install Wireshark first")


# ---------------------------------------------------------------------------
# Domain handling
# ---------------------------------------------------------------------------
# The "registered domain" is the part the attacker buys, e.g. example.attack
# or google.com. Everything to the LEFT of it is the "subdomain" - this is
# where tunnelling tools hide their encoded data.
# It is found with the Public Suffix List (tldextract library), so that
# bbc.co.uk and nutech.edu.pk are handled correctly. For lab TLDs that are
# not in the list (e.g. ".attack") the last 2 labels are used.

# Record types that normal client devices ask for every day.
# Anything else (NULL, TXT, MX, CNAME, SRV, KEY, PRIVATE ...) is "uncommon".
COMMON_QUERY_TYPES = {"A", "AAAA", "HTTPS", "PTR"}

# DNS record type numbers -> names (RFC 1035, RFC 3596, RFC 9460)
TYPE_NAMES = {
    "1": "A", "2": "NS", "5": "CNAME", "6": "SOA", "10": "NULL",
    "12": "PTR", "15": "MX", "16": "TXT", "25": "KEY", "28": "AAAA",
    "33": "SRV", "64": "SVCB", "65": "HTTPS", "255": "ANY",
    "65399": "PRIVATE",
}

# Behavioural feature: how many DIFFERENT subdomains of the same registered
# domain did this client ask for in the last N seconds?
BEHAVIOUR_WINDOW_SECONDS = 60

# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------
# Each rule = (feature column, direction, threshold taken from the literature
# or from the previous version of this project). step4_detect.py tests each
# rule with these values AND with a threshold tuned on the training data.
#   ">"  means "flag if feature > threshold"
#   "<"  means "flag if feature < threshold"
RULES = {
    "entropy":       ("entropy", ">", 4.0),        # Salat et al. (2023)
    "length":        ("sub_length", ">", 20),      # previous project version
    "longest_label": ("longest_label", ">", 40),   # labels are max 63 chars (RFC 1035)
    "label_count":   ("label_count", ">", 3),
    "record_type":   ("uncommon_type", ">", 0),    # 1 = type not in COMMON_QUERY_TYPES
    "ttl":           ("ttl", "<", 1),              # Salat et al.: TTL near zero
    "unique_subs":   ("unique_subs_60s", ">", 20), # behaviour over 60 s window
}

# Benign traffic types.
# REALISTIC = what normal users/devices produce -> used for tuning and for the
#             main false positive rate.
# STRESS    = legitimate but deliberately random-looking names (wildcard CDN
#             subdomains). Never used for tuning; its false positive rate is
#             reported separately as a worst case.
REALISTIC_BENIGN = {"benign_top_sites", "benign_own"}
STRESS_BENIGN = {"benign_wildcard"}

# Tuning: the highest false positive rate we accept on any realistic benign
# source when choosing a tuned threshold (0.01 = 1 false alarm per 100 lookups).
MAX_FPR = 0.01

# Combined rule: flag a query if at least this many single rules flag it.
VOTE_K = 2

RANDOM_SEED = 42
