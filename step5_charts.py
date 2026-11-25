"""
STEP 5 - CHARTS
Draw the figures used in the report.

  Input : data/3_features.csv, results/per_category.csv, results/rules_test.csv
  Output: results/fig1_feature_boxplots.png    feature values per traffic type
          results/fig2_entropy_vs_length.png   why entropy depends on length
          results/fig3_detection_heatmap.png   % of each traffic type flagged
          results/fig4_rules_compared.png      detection rate vs false positives
"""
import csv
import math
import random

import matplotlib
matplotlib.use("Agg")                    # draw to files, no window needed
import matplotlib.pyplot as plt

import config

BLUE, ORANGE = "#2a78d6", "#eb6834"      # malicious, benign
INK, INK_2, GRID = "#0b0b0b", "#52514e", "#e4e3df"
ORDER = ["benign_top_sites", "benign_own", "benign_wildcard", "iodine",
         "dnscat2", "dns2tcp", "iodine_A_mode", "cobaltstrike"]
NICE = {"benign_top_sites": "Benign\ntop sites", "benign_own": "Benign\nown capture",
        "benign_wildcard": "Benign\nwildcard", "iodine": "Iodine",
        "dnscat2": "DNScat2", "dns2tcp": "dns2tcp*",
        "iodine_A_mode": "Iodine\nA-mode*", "cobaltstrike": "Cobalt\nStrike*"}

plt.rcParams.update({"font.size": 9, "axes.edgecolor": INK_2, "axes.labelcolor": INK,
                     "xtick.color": INK_2, "ytick.color": INK_2,
                     "axes.spines.top": False, "axes.spines.right": False,
                     "figure.facecolor": "white", "savefig.dpi": 200})


def load_features():
    with open(config.FEATURES_CSV, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    groups = {}
    for r in rows:
        groups.setdefault(r["category"], []).append(r)
    return {c: groups[c] for c in ORDER if c in groups}


def read_table(path):
    with open(path) as f:
        return list(csv.DictReader(f))


def fig1_boxplots(groups):
    panels = [("entropy", "Shannon entropy (bits/char)", 4.0, "linear"),
              ("sub_length", "Subdomain length (chars)", 20, "linear"),
              ("ttl", "Answer TTL (s), no-answer removed", 1, "symlog"),
              ("unique_subs_60s", "Unique subdomains in 60 s", 20, "log")]
    fig, axes = plt.subplots(2, 2, figsize=(10, 7))
    names = list(groups)
    for ax, (col, title, line, scale) in zip(axes.flat, panels):
        data = []
        for c in names:
            vals = [float(r[col]) for r in groups[c]]
            if col == "ttl":
                vals = [v for v in vals if v >= 0] or [0]
            if scale == "log":
                vals = [max(v, 1) for v in vals]
            data.append(vals)
        box = ax.boxplot(data, patch_artist=True, showfliers=False, widths=0.6,
                         medianprops={"color": INK, "linewidth": 1.5})
        for patch, c in zip(box["boxes"], names):
            patch.set_facecolor(ORANGE if c.startswith("benign") else BLUE)
            patch.set_edgecolor("white")
        ax.axhline(line, color=INK_2, linestyle="--", linewidth=1)
        ax.text(0.55, line, f"rule = {line}", va="bottom", ha="left",
                color=INK_2, fontsize=8)
        if scale == "symlog":
            ax.set_yscale("symlog", linthresh=1)
            ax.set_ylim(bottom=0)
        else:
            ax.set_yscale(scale)
        ax.set_title(title, loc="left", color=INK)
        ax.set_xticks(range(1, len(names) + 1), [NICE[c] for c in names], fontsize=7)
        ax.grid(axis="y", color=GRID, linewidth=0.6)
    fig.legend(handles=[plt.Rectangle((0, 0), 1, 1, color=ORANGE),
                        plt.Rectangle((0, 0), 1, 1, color=BLUE)],
               labels=["Benign", "Tunnel"], loc="upper right", frameon=False)
    fig.suptitle("Feature values per traffic type (* = unseen tool, outliers hidden)",
                 x=0.02, ha="left", color=INK)
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    fig.savefig(f"{config.RESULTS_FOLDER}/fig1_feature_boxplots.png")
    plt.close(fig)


def fig2_entropy_vs_length(groups):
    random.seed(config.RANDOM_SEED)
    names = list(groups)
    cols = 4
    fig, axes = plt.subplots(math.ceil(len(names) / cols), cols,
                             figsize=(11, 5.5), sharex=True, sharey=True)
    xs = range(1, 241)
    bound = [math.log2(x) for x in xs]
    for ax, c in zip(axes.flat, names):
        sample = random.sample(groups[c], min(3000, len(groups[c])))
        ax.scatter([int(r["sub_length"]) for r in sample],
                   [float(r["entropy"]) for r in sample], s=8, alpha=0.35,
                   color=ORANGE if c.startswith("benign") else BLUE, linewidths=0)
        ax.plot(xs, bound, color=INK_2, linewidth=1)
        ax.axhline(4.0, color=INK_2, linestyle="--", linewidth=1)
        ax.set_title(NICE[c].replace("\n", " "), loc="left", color=INK, fontsize=9)
        ax.set_xlim(0, 240)
        ax.set_ylim(0, 7.5)
        ax.grid(color=GRID, linewidth=0.6)
    for ax in axes.flat[len(names):]:
        ax.axis("off")
    fig.supxlabel("Subdomain length (characters)", color=INK)
    fig.supylabel("Shannon entropy (bits/char)", color=INK)
    fig.suptitle("Entropy can never exceed log2(length) (solid curve); "
                 "dashed line = 4.0 threshold", x=0.02, ha="left", color=INK)
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(f"{config.RESULTS_FOLDER}/fig2_entropy_vs_length.png")
    plt.close(fig)


def fig3_heatmap():
    table = read_table(f"{config.RESULTS_FOLDER}/per_category.csv")
    table = [t for t in table if "tuned" not in t["rule"]]
    cats = [c for c in ORDER if c in table[0]]
    values = [[float(t[c]) for c in cats] for t in table]
    fig, ax = plt.subplots(figsize=(10, 4.8))
    image = ax.imshow(values, cmap="Blues", vmin=0, vmax=100, aspect="auto")
    for i, row in enumerate(values):
        for j, v in enumerate(row):
            ax.text(j, i, f"{v:.0f}", ha="center", va="center", fontsize=8,
                    color="white" if v > 55 else INK)
    ax.set_xticks(range(len(cats)), [NICE[c] for c in cats], fontsize=8)
    ax.set_yticks(range(len(table)),
                  [t["rule"].replace(" (literature)", "") for t in table], fontsize=8)
    ax.spines[:].set_visible(False)
    fig.colorbar(image, ax=ax, label="% of queries flagged")
    ax.set_title("% flagged per traffic type, literature thresholds "
                 "(benign columns = false positives)", loc="left", color=INK)
    fig.tight_layout()
    fig.savefig(f"{config.RESULTS_FOLDER}/fig3_detection_heatmap.png")
    plt.close(fig)


def fig4_rules_compared():
    table = read_table(f"{config.RESULTS_FOLDER}/rules_test.csv")
    table = [t for t in table if "tuned" not in t["rule"]]
    names = [t["rule"].replace(" (literature)", "") for t in table]
    detect = [float(t["detection_rate"]) for t in table]
    fpr = [float(t["fpr"]) for t in table]
    y = range(len(names))
    fig, ax = plt.subplots(figsize=(8, 4.5))
    ax.barh([i - 0.2 for i in y], detect, height=0.38, color=BLUE, label="Detection rate %")
    ax.barh([i + 0.2 for i in y], fpr, height=0.38, color=ORANGE, label="False positive rate %")
    for i, (d, f) in enumerate(zip(detect, fpr)):
        ax.text(d + 1, i - 0.2, f"{d:.1f}", va="center", fontsize=7, color=INK_2)
        ax.text(f + 1, i + 0.2, f"{f:.2f}", va="center", fontsize=7, color=INK_2)
    ax.set_yticks(list(y), names)
    ax.invert_yaxis()
    ax.set_xlim(0, 110)
    ax.grid(axis="x", color=GRID, linewidth=0.6)
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.4, -0.08), ncol=2)
    ax.set_title("Test split: detection vs false positives (literature thresholds)",
                 loc="left", color=INK)
    fig.tight_layout()
    fig.savefig(f"{config.RESULTS_FOLDER}/fig4_rules_compared.png")
    plt.close(fig)


def main():
    groups = load_features()
    fig1_boxplots(groups)
    fig2_entropy_vs_length(groups)
    fig3_heatmap()
    fig4_rules_compared()
    print(f"Saved 4 figures to {config.RESULTS_FOLDER}/")


if __name__ == "__main__":
    main()
