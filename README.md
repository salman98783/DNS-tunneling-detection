# DNS Tunneling Detection

A Python-based project for detecting DNS tunneling attacks using extracted DNS traffic features.

## Datasets

The project analyses three categories of DNS traffic:

- Iodine tunneling traffic
- DNScat2 tunneling traffic
- Benign DNS traffic

## Files

- `extract_features.py` — Extracts DNS features and creates `dns_features.csv`.
- `evaluate_detection.py` — Evaluates different detection techniques.
- `data/` — Contains the original CSV datasets.
- `dns_features.csv` — Contains the extracted features.

## Detection Techniques

The evaluation includes:

- Domain entropy
- Domain length
- Suspicious DNS record types
- Low TTL values
- Combined rule-based detection

## Usage

Extract the features:

```bash
python extract_features.py