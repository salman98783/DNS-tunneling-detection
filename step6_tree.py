"""
STEP 6 - DECISION TREE (simple machine learning)
Instead of choosing thresholds by hand, let a small decision tree learn
which features and thresholds separate tunnels from normal traffic.

Why a decision tree?  Its result is a set of if/else rules that can be
printed and read (results/tree_rules.txt), so it is NOT a black box -
it can be compared directly with the hand-made rules of step 4.

  Input : data/3_features.csv
  Output: results/tree_rules.txt     the learned if/else rules
          results/tree_results.csv   test / wildcard / unseen-tool results
"""
import csv

from sklearn.tree import DecisionTreeClassifier, export_text

import config
from step4_detect import NUMERIC, load_rows, measures

MAX_DEPTH = 3          # at most 3 questions per decision -> easy to read

# Two experiments:
#  A) the tree may use every feature
#  B) the tree may NOT use the record type. Experiment A shows the tree takes a
#     "shortcut": it only learns the record type, so tunnels that use normal
#     A records are missed. B forces it to learn from the name and behaviour.
FEATURE_SETS = {
    "A_all_features": NUMERIC,
    "B_without_record_type": [c for c in NUMERIC if c != "uncommon_type"],
}


def to_matrix(rows, features):
    return [[r[c] for c in features] for r in rows], [r["label"] for r in rows]


def main():
    rows = load_rows()
    stress = [r for r in rows if r["category"] in config.STRESS_BENIGN]
    normal = [r for r in rows if r["category"] not in config.STRESS_BENIGN]
    train = [r for r in normal if r["split"] == "train"]
    test = [r for r in normal if r["split"] == "test"]
    unseen = [r for r in rows if r["split"] == "unseen"]

    results = []
    rules_file = open(f"{config.RESULTS_FOLDER}/tree_rules.txt", "w")
    for experiment, features in FEATURE_SETS.items():
        # class_weight="balanced": benign and tunnel rows count equally,
        # even though there are more tunnel rows
        tree = DecisionTreeClassifier(max_depth=MAX_DEPTH, class_weight="balanced",
                                      random_state=config.RANDOM_SEED)
        tree.fit(*to_matrix(train, features))

        rules_text = export_text(tree, feature_names=features)
        rules_file.write(f"=== {experiment} (class 1 = tunnel) ===\n{rules_text}\n")
        print(f"\n=== {experiment} (class 1 = tunnel) ===\n{rules_text}")

        def evaluate(group):
            x, y = to_matrix(group, features)
            pred = tree.predict(x)
            tp = sum(1 for p, t in zip(pred, y) if p == 1 and t == 1)
            fp = sum(1 for p, t in zip(pred, y) if p == 1 and t == 0)
            tn = sum(1 for p, t in zip(pred, y) if p == 0 and t == 0)
            fn = sum(1 for p, t in zip(pred, y) if p == 0 and t == 1)
            return measures(tp, fp, tn, fn)

        groups = [("test split", test)]
        for cat in sorted({r["category"] for r in test if r["label"] == 0}):
            groups.append((f"test benign: {cat}", [r for r in test if r["category"] == cat]))
        if stress:
            groups.append(("benign wildcard (stress)", stress))
        for tool in sorted({r["category"] for r in unseen}):
            groups.append((f"unseen: {tool}", [r for r in unseen if r["category"] == tool]))
        for name, group in groups:
            results.append({"experiment": experiment, "evaluated_on": name,
                            **evaluate(group)})
    rules_file.close()

    with open(f"{config.RESULTS_FOLDER}/tree_results.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(results[0].keys()))
        writer.writeheader()
        writer.writerows(results)
    for r in results:
        print(f"{r['experiment']:<24}{r['evaluated_on']:<32} detect={r['detection_rate']:>6}%  "
              f"FPR={r['fpr']:>6}%")


if __name__ == "__main__":
    main()
