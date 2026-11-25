# DNS Tunnelling Detection – a comparison of open-source detection techniques

This tool reads DNS traffic from packet captures (PCAP), calculates features for
every DNS lookup, applies seven detection rules (plus combined rules and a small
decision tree), and measures how well each one separates tunnelling traffic from
normal traffic. It tests the rules on traffic that was **never** used to choose
their thresholds, including three tunnelling tools that were never seen at all.

## Pipeline

```
 PCAP files ──► step1_extract ──► step2_clean ──► step3_features ──► step4_detect ──► step5_charts
 (sources.csv)   tshark → CSV      duplicates,     entropy, length,    rules, tuning,     figures
                                   TTL, types      TTL, behaviour      evaluation
                                                                  └──► step6_tree (decision tree)
```

Every step writes its own file, so any stage can be opened and checked:

| Step | Script | Output |
|---|---|---|
| 1 | `step1_extract.py` | `data/1_extracted.csv` – one row per DNS response seen by the client |
| 2 | `step2_clean.py` | `data/2_cleaned.csv`, `results/cleaning_log.csv` |
| 3 | `step3_features.py` | `data/3_features.csv` |
| 4 | `step4_detect.py` | `results/thresholds.csv`, `rules_test.csv`, `per_category.csv`, `unseen_tools.csv` |
| 5 | `step5_charts.py` | `results/fig1…fig4*.png` |
| 6 | `step6_tree.py` | `results/tree_rules.txt`, `tree_results.csv` |

All thresholds and settings are in **`config.py`**. Which PCAP is benign or malicious,
and whether it is used for training, testing or as an unseen tool, is in **`sources.csv`**.

## Setup (Windows)

1. Install **Wireshark** (it includes `tshark`) – https://www.wireshark.org
2. Install **Python 3.10+** from python.org (3.13 recommended)
3. In this folder:
   ```
   pip install -r requirements.txt
   python get_datasets.py        # downloads the public PCAPs (≈300 MB, no git needed) into data/pcaps
   python run_all.py             # runs steps 1-6
   python tests/test_features.py # unit tests
   ```

## Data

| Category | Source | Split | Role |
|---|---|---|---|
| `iodine` (24 configs: NULL/TXT/CNAME/MX/SRV/PRIVATE × Base32/64/128/Raw) | Korving (2023) | Base32+Base128 → train, Base64+Raw → test | known tool |
| `dnscat2` | Korving (2023) | file transfer → train, C2 → test | known tool |
| `dns2tcp` (8 configs) | Korving (2023) | unseen | never used for tuning |
| `iodine_A_mode` | Gao et al. (2024) | unseen | uses normal A records |
| `cobaltstrike` | Gao et al. (2024) | unseen | commercial C2 beacon |
| `benign_top_sites` | Gao et al. (2024) | 3 files train / 3 test | realistic benign |
| `benign_wildcard` | Gao et al. (2024) | test only | **stress test**: legitimate but random-looking names |
| `benign_own` | own Wireshark capture (laptop, Wi-Fi, 7 Nov 2026, 1 h 46 min) | first half → train, second half → test | realistic benign |

**Only responses sent to the client are kept** (`client_ip` in `sources.csv`). The
tunnelling datasets were captured on the DNS resolver, so every lookup appears twice
(resolver→client and authoritative server→resolver); we keep the client's view.

### Adding your own capture
1. Turn off "secure DNS / DNS over HTTPS" in the browser, run `ipconfig /flushdns`.
2. Wireshark capture filter `port 53`, browse normally, save as `.pcapng` into `data/pcaps/`.
3. Add a line to `sources.csv`, e.g.
   `own_capture_session1.pcapng,0,benign_own,laptop_browsing,train,any`
4. `python run_all.py`

## Features

| Feature | Meaning |
|---|---|
| `entropy` | Shannon entropy of the subdomain, H = −Σ p(c)·log2 p(c). Max = log2(alphabet size): hex 4.0, Base32 5.0, Base64 6.0, and never above log2(length) |
| `sub_length` | characters in the subdomain (without dots) |
| `label_count`, `longest_label` | number of labels / longest label (max 63, RFC 1035) |
| `uncommon_type` | 1 if the record type is not A, AAAA, HTTPS or PTR |
| `ttl` | smallest answer TTL; −1 when there is no answer |
| `unique_subs_60s` | different subdomains of the same registered domain asked by the same client in the last 60 s (behaviour) |

The registered domain is found with the Public Suffix List (`tldextract`, offline copy).

## Evaluation

* Thresholds: the **literature** value (config.py) and a value **tuned on the training
  split**: the threshold that detects the most tunnels while keeping the false positive
  rate at or below 1% (`MAX_FPR`) on **every** benign source. Each traffic category
  counts equally, so the large public dataset cannot drown out the own capture.
* Reported on the **test split** only: TP/FP/TN/FN, detection rate, FPR, precision, F1,
  balanced accuracy. Plain accuracy is not used because the classes are unbalanced.
* False positives are reported separately for realistic benign traffic and for the
  wildcard stress test.

## References
* Korving, F. (2023) DNS tunnel dataset. ICCWS 2023, doi:10.34190/iccws.18.1.962
* Gao et al. (2024) GraphTunnel: Robust DNS tunnel detection based on DNS recursive resolution graph. IEEE.
* Salat, L., Davis, M. and Khan, N. (2023) DNS tunnelling, exfiltration and detection over cloud environments. *Sensors*, 23(5), 2760.
