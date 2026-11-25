"""
STEP 3 - FEATURES
Calculate the numbers (features) that the detection rules look at.

  Input : data/2_cleaned.csv
  Output: data/3_features.csv

Example: name = "lacekhq4hpyit1ex.vb2.example.attack"
  registered_domain = "example.attack"           (what the attacker owns)
  subdomain         = "lacekhq4hpyit1ex.vb2"     (where the data is hidden)

Payload features (look at ONE query):
  sub_length     characters in the subdomain, without dots      -> 19
  entropy        Shannon entropy of the subdomain characters     -> ~3.9
  label_count    how many labels the subdomain has               -> 2
  longest_label  length of the longest label                     -> 16
  uncommon_type  1 if record type is not A/AAAA/HTTPS/PTR        -> 0 or 1
  ttl            smallest answer TTL (-1 = no answer)            (from step 2)

Behaviour feature (looks at MANY queries over time):
  unique_subs_60s  how many DIFFERENT subdomains of the same registered
                   domain this client asked for in the last 60 seconds.
                   A tunnel needs a new name for every chunk of data, so
                   this number grows quickly.
"""
import csv
import math
from collections import Counter, defaultdict, deque

import tldextract

import config

# Offline copy of the Public Suffix List (bundled with tldextract)
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


def split_name(qname):
    """Return (subdomain, registered_domain) for a domain name."""
    parts = _extract(qname)
    if parts.suffix:                                  # normal internet name
        return parts.subdomain, f"{parts.domain}.{parts.suffix}"
    labels = qname.split(".")                         # lab TLD, e.g. .attack
    return ".".join(labels[:-2]), ".".join(labels[-2:])


def shannon_entropy(text):
    """
    H = -sum( p(c) * log2(p(c)) ) over every different character c.
    p(c) = how often c appears / length of the text.
    Result is in bits per character. Maximum possible value is
    log2(number of different characters), e.g. 4.0 for hex (16 symbols).
    """
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def payload_features(qname, qtype):
    """All features that can be calculated from one query on its own."""
    subdomain, registered = split_name(qname)
    labels = [l for l in subdomain.split(".") if l]
    joined = "".join(labels)                          # dots are separators, not data
    return {
        "registered_domain": registered,
        "subdomain": subdomain,
        "sub_length": len(joined),
        "entropy": round(shannon_entropy(joined), 4),
        "label_count": len(labels),
        "longest_label": max((len(l) for l in labels), default=0),
        "uncommon_type": 0 if qtype in config.COMMON_QUERY_TYPES else 1,
    }


def add_behaviour_feature(rows):
    """
    For every row, count the different subdomains of the same registered
    domain that the same client asked for in the last WINDOW seconds.
    Rows must be sorted by time. Each (file, client, domain) has its own
    sliding window.
    """
    window = config.BEHAVIOUR_WINDOW_SECONDS
    recent = defaultdict(deque)        # key -> deque of (time, subdomain)
    counts = defaultdict(Counter)      # key -> how often each subdomain is in the window
    for r in rows:
        key = (r["source_file"], r["client"], r["registered_domain"])
        now = float(r["time"])
        q, c = recent[key], counts[key]
        while q and now - q[0][0] > window:          # forget old queries
            _, old_sub = q.popleft()
            c[old_sub] -= 1
            if c[old_sub] == 0:
                del c[old_sub]
        q.append((now, r["subdomain"]))
        c[r["subdomain"]] += 1
        r["unique_subs_60s"] = len(c)


def main():
    with open(config.CLEANED_CSV, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    for r in rows:
        r.update(payload_features(r["qname"], r["qtype"]))
    rows.sort(key=lambda r: (r["source_file"], float(r["time"])))
    add_behaviour_feature(rows)

    columns = list(rows[0].keys())
    with open(config.FEATURES_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Calculated features for {len(rows)} rows -> {config.FEATURES_CSV}")


if __name__ == "__main__":
    main()
