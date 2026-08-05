import csv

rows = []
file = open("dns_features.csv", "r", encoding="utf-8")
reader = csv.DictReader(file)
for line in reader:
    rows.append(line)
file.close()

print("Total rows loaded:", len(rows))

def test_rule(rows, rule_function, rule_name):
    true_positive = 0
    false_positive = 0
    true_negative = 0
    false_negative = 0

    for row in rows:
        actual_malicious = (row["label"] == "1")
        flagged = rule_function(row)

        if actual_malicious and flagged:
            true_positive = true_positive + 1
        elif actual_malicious and not flagged:
            false_negative = false_negative + 1
        elif not actual_malicious and flagged:
            false_positive = false_positive + 1
        else:
            true_negative = true_negative + 1

    total_malicious = true_positive + false_negative
    total_benign = false_positive + true_negative
    total = len(rows)

    detection_rate = 0
    if total_malicious > 0:
        detection_rate = true_positive / total_malicious

    false_positive_rate = 0
    if total_benign > 0:
        false_positive_rate = false_positive / total_benign

    accuracy = (true_positive + true_negative) / total

    print("")
    print("Technique:", rule_name)
    print("  Detection rate (TPR):", round(detection_rate * 100, 2), "%")
    print("  False positive rate:", round(false_positive_rate * 100, 2), "%")
    print("  Accuracy:", round(accuracy * 100, 2), "%")
    print("  (TP=", true_positive, " FP=", false_positive, " TN=", true_negative, " FN=", false_negative, ")")


# Technique 1: Shannon entropy > 4.0 

def rule_entropy(row):
    return float(row["entropy"]) > 4.0

test_rule(rows, rule_entropy, "Shannon entropy > 4.0")


#  Technique 2: subdomain length 

def rule_length(row):
    return int(row["subdomain_length"]) > 20

test_rule(rows, rule_length, "Subdomain length > 20 characters")


#  Technique 3: record type 

def rule_record_type(row):
    suspicious_types = ["NULL", "TXT", "CNAME", "MX"]
    return row["record_type"] in suspicious_types

test_rule(rows, rule_record_type, "Suspicious record type (NULL/TXT/CNAME/MX)")


#  Technique 4: TTL 

def rule_ttl(row):
    ttl = int(row["ttl"])
    return ttl >= 0 and ttl < 100

test_rule(rows, rule_ttl, "TTL < 100 seconds")


# Technique 5: combined rule 

def rule_combined(row):
    return rule_entropy(row) or rule_length(row) or rule_record_type(row) or rule_ttl(row)

test_rule(rows, rule_combined, "Combined (entropy OR length OR record type OR TTL)")
