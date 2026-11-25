"""
Unit tests - small examples worked out by hand, checked against the code.
Run:  python tests/test_features.py      (or: python -m pytest tests)
"""
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from step2_clean import smallest_ttl, type_name
from step3_features import add_behaviour_feature, payload_features, shannon_entropy, split_name
from step4_detect import measures, rule_flags, tune_threshold


def test_entropy_hand_examples():
    assert shannon_entropy("") == 0
    assert shannon_entropy("aaaa") == 0                    # one symbol -> no surprise
    assert shannon_entropy("abab") == 1                    # 2 symbols, equal -> 1 bit
    assert shannon_entropy("abcd") == 2                    # 4 symbols, equal -> 2 bits
    assert math.isclose(shannon_entropy("mail"), 2.0)      # 4 different letters


def test_entropy_upper_bounds():
    hex_text = "0123456789abcdef" * 4
    assert math.isclose(shannon_entropy(hex_text), 4.0)    # hex can never exceed 4.0
    for n in (5, 10, 16):                                  # never above log2(length)
        assert shannon_entropy("abcdefghijklmnop"[:n]) <= math.log2(n) + 1e-9


def test_split_name():
    assert split_name("www.bbc.co.uk") == ("www", "bbc.co.uk")
    assert split_name("google.com") == ("", "google.com")
    assert split_name("abc.def.example.attack") == ("abc.def", "example.attack")


def test_payload_features():
    f = payload_features("ab12.cd.example.attack", "TXT")
    assert f["sub_length"] == 6            # dots are not counted
    assert f["label_count"] == 2
    assert f["longest_label"] == 4
    assert f["uncommon_type"] == 1
    assert payload_features("www.google.com", "A")["uncommon_type"] == 0


def test_cleaning_helpers():
    assert smallest_ttl("300,60,120") == 60
    assert smallest_ttl("") == -1
    assert type_name("16") == "TXT"
    assert type_name("9999") == "TYPE9999"


def test_behaviour_window():
    rows = [{"source_file": "f", "client": "c", "registered_domain": "x.com",
             "time": t, "subdomain": s}
            for t, s in [(0, "a"), (1, "b"), (2, "a"), (100, "c")]]
    add_behaviour_feature(rows)
    assert [r["unique_subs_60s"] for r in rows] == [1, 2, 2, 1]   # old ones expire


def test_rules_and_measures():
    assert rule_flags({"entropy": 4.5}, "entropy", ">", 4.0)
    assert not rule_flags({"ttl": -1}, "ttl", "<", 1)       # no answer is never flagged
    m = measures(tp=8, fp=1, tn=9, fn=2)
    assert m["detection_rate"] == 80.0 and m["fpr"] == 10.0


def test_tune_threshold_finds_the_gap():
    rows = [{"label": 0, "x": v} for v in (1, 2, 3)] + \
           [{"label": 1, "x": v} for v in (7, 8, 9)]
    threshold, detection, fpr = tune_threshold(rows, "x", ">")
    assert 3 <= threshold < 7 and detection == 100.0 and fpr == 0.0


if __name__ == "__main__":
    tests = [v for k, v in dict(globals()).items() if k.startswith("test_")]
    for t in tests:
        t()
        print(f"PASS  {t.__name__}")
    print(f"\nAll {len(tests)} tests passed")
