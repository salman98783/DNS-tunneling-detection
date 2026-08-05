import csv
import math


def calc_entropy(text):
    if len(text) == 0:
        return 0
    counts = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1

    entropy = 0
    for ch in counts:
        p = counts[ch] / len(text)
        entropy = entropy - p * math.log2(p)
    return entropy


def get_subdomain(full_name):
    # take the first label of the domain name
    parts = full_name.split(".")
    return parts[0]


type_names = {
    "1": "A",
    "5": "CNAME",
    "10": "NULL",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "65": "HTTPS",
}

def get_type_name(type_number):
    if type_number in type_names:
        return type_names[type_number]
    return type_number


def get_first_ttl(ttl_field):
    if ttl_field == "":
        return -1
    first_value = ttl_field.split(",")[0]
    return int(first_value)

def read_data_file(path):
    rows = []
    file = open(path, "r", encoding="utf-8", errors="ignore")
    for line in file:
        line = line.strip()
        if line == "":
            continue
        parts = line.split(",")
        if len(parts) < 3:
            continue
        name = parts[0]
        record_type = get_type_name(parts[1])
        ttl = get_first_ttl(parts[2])
        rows.append((name, record_type, ttl))
    file.close()
    return rows

iodine_rows = read_data_file("data/iodine.csv")
dnscat2_rows = read_data_file("data/dnscat2.csv")
benign_rows = read_data_file("data/benign.csv")

print("Iodine rows:", len(iodine_rows))
print("DNScat2 rows:", len(dnscat2_rows))
print("Benign rows:", len(benign_rows))

output_file = open("dns_features.csv", "w", newline="", encoding="utf-8")
writer = csv.writer(output_file)
writer.writerow(["query_name", "record_type", "subdomain_length", "entropy", "ttl", "label", "source"])

def add_rows(rows, label, source_name):
    for name, record_type, ttl in rows:
        sub = get_subdomain(name)
        length = len(sub)
        entropy = calc_entropy(sub)
        writer.writerow([name, record_type, length, round(entropy, 3), ttl, label, source_name])

add_rows(iodine_rows, 1, "iodine")
add_rows(dnscat2_rows, 1, "dnscat2")
add_rows(benign_rows, 0, "benign")

output_file.close()
print("Saved to dns_features.csv")
