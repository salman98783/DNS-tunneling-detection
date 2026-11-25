"""
STEP 4 - DETECT AND EVALUATE
Apply every detection rule and measure how well it works.

  Input : data/3_features.csv
  Output: results/thresholds.csv     which threshold each rule used
          results/rules_test.csv     main results on the TEST split
          results/per_category.csv   % of each traffic type flagged by each rule
          results/unseen_tools.csv   detection of tools never used for tuning

Method
  1. Every rule is tested twice:
       a) with the threshold from the literature (config.RULES)
       b) with a threshold TUNED on the TRAINING split only: the one that
          detects the most tunnels while keeping false alarms at or below
          config.MAX_FPR (1%) on every benign source (see tune_threshold).
  2. Results are reported on the TEST split (files never used for tuning),
     and on UNSEEN tools (dns2tcp, Iodine A-mode, Cobalt Strike).
  3. A combined "vote" rule flags a query when at least K rules flag it.

Measures (TP/FP/TN/FN = true/false positives/negatives)
  detection rate (recall, TPR) = TP / (TP + FN)
  false positive rate (FPR)    = FP / (FP + TN)
  precision                    = TP / (TP + FP)
  F1                           = 2 * precision * recall / (precision + recall)
  balanced accuracy            = (TPR + (1 - FPR)) / 2
Plain accuracy is NOT used as the main measure: when one class is much
bigger, a rule that flags everything can still get high accuracy.
"""
import csv
from collections import Counter, defaultdict

import config

NUMERIC = ["sub_length", "entropy", "label_count", "longest_label",
           "uncommon_type", "ttl", "unique_subs_60s"]


def load_rows():
    with open(config.FEATURES_CSV, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for r in rows:
        r["label"] = int(r["label"])
        for col in NUMERIC:
            r[col] = float(r[col])
    return rows


def rule_flags(row, feature, direction, threshold):
    """True if this row is flagged by the rule."""
    value = row[feature]
    if feature == "ttl" and value < 0:        # no answer -> no TTL to judge
        return False
    return value > threshold if direction == ">" else value < threshold


def confusion(rows, flag_function):
    """Count TP, FP, TN, FN for a function that returns True = 'malicious'."""
    tp = fp = tn = fn = 0
    for r in rows:
        flagged = flag_function(r)
        if r["label"] == 1:
            tp, fn = (tp + 1, fn) if flagged else (tp, fn + 1)
        else:
            fp, tn = (fp + 1, tn) if flagged else (fp, tn + 1)
    return tp, fp, tn, fn


def measures(tp, fp, tn, fn):
    tpr = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    f1 = 2 * precision * tpr / (precision + tpr) if precision + tpr else 0.0
    return {"TP": tp, "FP": fp, "TN": tn, "FN": fn,
            "detection_rate": round(tpr * 100, 2), "fpr": round(fpr * 100, 2),
            "precision": round(precision * 100, 2), "f1": round(f1 * 100, 2),
            "balanced_acc": round((tpr + 1 - fpr) / 2 * 100, 2)}


def tune_threshold(train_rows, feature, direction):
    """
    Choose a threshold the way a security team would:
      "catch as many tunnels as possible, but raise a false alarm on at most
       MAX_FPR (1%) of the normal traffic from ANY benign source".

    Every traffic CATEGORY counts equally:
      detection rate = average over the tunnel categories (iodine, dnscat2 ...)
      false pos rate = checked for EACH benign category (top sites, own capture)
                       and the WORST one must stay within MAX_FPR.
    Without this, the biggest dataset would decide the threshold on its own:
    45,000 top-site rows would drown out 1,600 rows of real browsing.

    Returns (threshold, detection rate on train, worst false positive rate on train).
    """
    rows = [r for r in train_rows if not (feature == "ttl" and r[feature] < 0)]
    # how many rows of each category have each feature value
    counts = defaultdict(Counter)
    sizes = Counter()
    label_of = {}
    for r in train_rows:
        cat = r.get("category", r["label"])
        sizes[cat] += 1
        label_of[cat] = r["label"]
    for r in rows:
        counts[r.get("category", r["label"])][r[feature]] += 1
    tunnel_cats = [c for c in sizes if label_of[c] == 1]
    benign_cats = [c for c in sizes if label_of[c] == 0]

    values = sorted({v for c in counts for v in counts[c]})
    # Walk through the values once, keeping a running count of rows that
    # would be flagged (for ">": values above t; for "<": values below t).
    if direction == ">":
        values.reverse()                          # start from the largest
    best = (-1.0, None, None)                     # (detection, threshold, fpr)
    flagged = Counter()                           # category -> rows flagged so far
    for t in values:
        tpr = sum(flagged[c] / sizes[c] for c in tunnel_cats) / len(tunnel_cats)
        worst_fpr = max(flagged[c] / sizes[c] for c in benign_cats)
        if worst_fpr <= config.MAX_FPR and tpr > best[0]:
            best = (tpr, t, worst_fpr)            # rows strictly beyond t are flagged
        for c in counts:                          # now include value t itself
            flagged[c] += counts[c][t]
    tpr, threshold, fpr = best
    return threshold, round(tpr * 100, 2), round(fpr * 100, 2)


def write_csv(path, rows):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main():
    rows = load_rows()
    stress = [r for r in rows if r["category"] in config.STRESS_BENIGN]
    normal = [r for r in rows if r["category"] not in config.STRESS_BENIGN]
    train = [r for r in normal if r["split"] == "train"]
    test = [r for r in normal if r["split"] == "test"]
    unseen = [r for r in rows if r["split"] == "unseen"]
    print(f"train={len(train)}  test={len(test)}  unseen={len(unseen)}  "
          f"stress(wildcard)={len(stress)}")

    # 1. build the list of rules: literature version + tuned version
    rules = {}
    threshold_rows = []
    for name, (feature, direction, lit_t) in config.RULES.items():
        tuned_t, train_tpr, train_fpr = tune_threshold(train, feature, direction)
        rules[f"{name} (literature)"] = (feature, direction, lit_t)
        rules[f"{name} (tuned)"] = (feature, direction, tuned_t)
        threshold_rows.append({"rule": name, "feature": feature,
                               "direction": direction, "literature": lit_t,
                               "tuned_on_train": tuned_t,
                               "train_detection_%": train_tpr,
                               "train_worst_fpr_%": train_fpr})
    write_csv(f"{config.RESULTS_FOLDER}/thresholds.csv", threshold_rows)

    # 2. combined rules, built once from the literature versions of every
    #    single rule and once from the tuned versions
    all_checks = {name: (lambda r, rule=rule: rule_flags(r, *rule))
                  for name, rule in rules.items()}
    for version in ("literature", "tuned"):
        group = [rules[f"{n} ({version})"] for n in config.RULES]

        def vote(r, group=group):
            return sum(rule_flags(r, *rule) for rule in group) >= config.VOTE_K

        def any_rule(r, group=group):
            return any(rule_flags(r, *rule) for rule in group)

        all_checks[f"combined >= {config.VOTE_K} agree ({version})"] = vote
        all_checks[f"combined any rule ({version})"] = any_rule

    # 3. main results on the test split
    results = []
    for name, check in all_checks.items():
        line = {"rule": name, **measures(*confusion(test, check))}
        line["fpr_wildcard"] = round(100 * sum(map(check, stress)) / len(stress), 2) if stress else ""
        results.append(line)
    write_csv(f"{config.RESULTS_FOLDER}/rules_test.csv", results)

    # 4. % flagged per traffic category (test + stress + unseen)
    evaluated = test + stress + unseen
    categories = sorted({r["category"] for r in evaluated})
    per_cat = []
    for name, check in all_checks.items():
        line = {"rule": name}
        for cat in categories:
            group = [r for r in evaluated if r["category"] == cat]
            line[cat] = round(100 * sum(map(check, group)) / len(group), 2)
        per_cat.append(line)
    write_csv(f"{config.RESULTS_FOLDER}/per_category.csv", per_cat)

    # 5. unseen tools: detection rate only (all rows are malicious)
    unseen_rows = []
    for name, check in all_checks.items():
        line = {"rule": name}
        for tool in sorted({r["category"] for r in unseen}):
            group = [r for r in unseen if r["category"] == tool]
            line[tool] = round(100 * sum(map(check, group)) / len(group), 2)
        unseen_rows.append(line)
    write_csv(f"{config.RESULTS_FOLDER}/unseen_tools.csv", unseen_rows)

    print(f"\n{'rule':<34}{'detect%':>9}{'FPR%':>8}{'prec%':>8}{'F1%':>8}"
          f"{'bal.acc%':>10}{'FPR wildcard%':>15}")
    for r in results:
        print(f"{r['rule']:<34}{r['detection_rate']:>9}{r['fpr']:>8}"
              f"{r['precision']:>8}{r['f1']:>8}{r['balanced_acc']:>10}"
              f"{r['fpr_wildcard']:>15}")
    print(f"\nSaved results to {config.RESULTS_FOLDER}/")


if __name__ == "__main__":
    main()
