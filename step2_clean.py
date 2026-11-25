"""
STEP 2 - CLEAN
Make the extracted rows consistent and remove anything that would distort
the results. Every step prints how many rows it removed, and the counts are
saved to results/cleaning_log.csv (evidence for the report).

  Input : data/1_extracted.csv
  Output: data/2_cleaned.csv

Cleaning steps
  1. Remove rows with no domain name (nothing to analyse).
  2. Remove exact duplicate responses (same file + transaction ID + name + type).
     These are retransmissions: counting them twice would inflate results.
  3. Remove the trailing dot from names ("google.com." -> "google.com").
  4. Turn the record type number into its name (16 -> "TXT").
  5. Reduce the list of answer TTLs to ONE value: the smallest TTL.
     No answer records -> TTL = -1 (meaning "no TTL available").
"""
import csv

import config


def type_name(type_number):
    """16 -> 'TXT'. Unknown numbers are kept as 'TYPE<n>'."""
    return config.TYPE_NAMES.get(type_number, f"TYPE{type_number}")


def smallest_ttl(ttl_text):
    """'300,60,120' -> 60.  '' (no answers) -> -1."""
    values = [int(v) for v in ttl_text.split(",") if v.strip().isdigit()]
    return min(values) if values else -1


def main():
    with open(config.EXTRACTED_CSV, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    log = [("rows extracted", len(rows))]

    # 1. remove empty names
    rows = [r for r in rows if r["qname"].strip()]
    log.append(("after removing empty names", len(rows)))

    # 2. remove exact duplicates (retransmissions)
    seen = set()
    unique_rows = []
    for r in rows:
        key = (r["source_file"], r["dns_id"], r["qname"], r["qtype_num"])
        if key not in seen:
            seen.add(key)
            unique_rows.append(r)
    rows = unique_rows
    log.append(("after removing duplicate responses", len(rows)))

    # 3-5. normalise the fields
    for r in rows:
        r["qname"] = r["qname"].rstrip(".")
        r["qtype"] = type_name(r["qtype_num"].split(",")[0])
        r["ttl"] = smallest_ttl(r["ttls"])

    columns = ["source_file", "label", "category", "config", "split", "time",
               "client", "qname", "qtype", "rcode", "answers", "ttl"]
    with open(config.CLEANED_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    with open(f"{config.RESULTS_FOLDER}/cleaning_log.csv", "w", newline="") as f:
        csv.writer(f).writerows([("step", "rows")] + log)
    for step, count in log:
        print(f"{step:<40} {count:>8}")
    print(f"\nSaved {config.CLEANED_CSV}")


if __name__ == "__main__":
    main()
