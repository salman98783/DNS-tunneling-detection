"""
run_all.py - run the whole pipeline from PCAP files to results and charts.
    python run_all.py
Each step can also be run on its own, e.g.  python step3_features.py
"""
import os
import time

import config
import step1_extract
import step2_clean
import step3_features
import step4_detect
import step5_charts
import step6_tree

STEPS = [("1. Extract DNS responses from PCAPs (tshark)", step1_extract),
         ("2. Clean the data", step2_clean),
         ("3. Calculate features", step3_features),
         ("4. Apply detection rules and evaluate", step4_detect),
         ("5. Draw charts", step5_charts),
         ("6. Decision tree experiment", step6_tree)]

if __name__ == "__main__":
    os.makedirs(config.RESULTS_FOLDER, exist_ok=True)
    for title, module in STEPS:
        print(f"\n{'=' * 70}\n{title}\n{'=' * 70}")
        start = time.time()
        module.main()
        print(f"({time.time() - start:.1f} s)")
