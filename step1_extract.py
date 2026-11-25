"""
STEP 1 - EXTRACT
Turn every PCAP listed in sources.csv into rows of a CSV file using tshark.

  Input : data/pcaps/*.pcap  +  sources.csv
  Output: data/1_extracted.csv   (one row = one DNS RESPONSE seen by the client)

Why only responses?
  A response contains EVERYTHING about one lookup: the name that was asked
  (question section), the record type, the answer TTL and the result code.
  So one response = one complete DNS lookup, and we never count the same
  lookup twice (query + response).

Why only responses sent TO the client (victim)?
  The tunnelling datasets were captured on the DNS resolver, so each lookup
  appears twice: resolver->victim and authoritative server->resolver.
  We keep only the victim's view, which is what a defender would monitor.
"""
import csv
import os
import subprocess

import config

# The DNS fields we ask tshark for (names are the same as in Wireshark's
# display-filter box, so they can be shown live in Wireshark during the viva).
TSHARK_FIELDS = [
    "frame.time_epoch",   # when the packet was captured (seconds)
    "ip.dst",             # who received the response (IPv4)
    "ipv6.dst",           # who received the response (IPv6)
    "dns.id",             # transaction ID - links query and response
    "dns.qry.name",       # the domain name that was looked up
    "dns.qry.type",       # record type number (1=A, 10=NULL, 16=TXT ...)
    "dns.flags.rcode",    # result code (0=OK, 3=NXDOMAIN ...)
    "dns.count.answers",  # how many answer records came back
    "dns.resp.ttl",       # TTL of each answer record (comma separated)
]

OUTPUT_COLUMNS = ["source_file", "label", "category", "config", "split",
                  "time", "client", "dns_id", "qname", "qtype_num",
                  "rcode", "answers", "ttls"]


def read_sources(path):
    """Read sources.csv, skipping comment lines that start with '#'."""
    with open(path, encoding="utf-8") as f:
        lines = [line for line in f if line.strip() and not line.startswith("#")]
    return list(csv.DictReader(lines))


def build_filter(client_ip):
    """Wireshark display filter: DNS responses (optionally only to one client)."""
    flt = "dns.flags.response == 1"
    if client_ip != "any":
        ip_field = "ipv6.dst" if ":" in client_ip else "ip.dst"
        flt += f" && {ip_field} == {client_ip}"
    return flt


def run_tshark(pcap_path, display_filter):
    """Run tshark and return its output as a list of field-lists."""
    command = [config.find_tshark(), "-r", pcap_path, "-Y", display_filter,
               "-T", "fields", "-E", "separator=\t", "-E", "occurrence=a",
               "-E", "aggregator=,"]
    for field in TSHARK_FIELDS:
        command += ["-e", field]
    # latin-1 maps every byte to exactly one character, so the binary bytes
    # used by Iodine's RAW encoding are kept (not replaced by '?').
    result = subprocess.run(command, capture_output=True, text=True,
                            encoding="latin-1")
    if result.returncode != 0:
        raise RuntimeError(f"tshark failed on {pcap_path}:\n{result.stderr}")
    return [line.split("\t") for line in result.stdout.splitlines()]


def main():
    sources = read_sources(config.SOURCES_FILE)
    with open(config.EXTRACTED_CSV, "w", newline="", encoding="utf-8") as out:
        writer = csv.writer(out)
        writer.writerow(OUTPUT_COLUMNS)
        for src in sources:
            pcap_path = f"{config.PCAP_FOLDER}/{src['file']}"
            if not os.path.exists(pcap_path):
                raise SystemExit(f"Missing {pcap_path} - run 'python get_datasets.py' "
                                 f"first, or remove this line from {config.SOURCES_FILE}")
            rows = run_tshark(pcap_path, build_filter(src["client_ip"]))
            for f in rows:
                time, ip4, ip6, dns_id, qname, qtype, rcode, answers, ttls = f
                writer.writerow([src["file"], src["label"], src["category"],
                                 src["config"], src["split"], time, ip4 or ip6,
                                 dns_id, qname, qtype, rcode, answers, ttls])
            print(f"{src['file']:<55} {len(rows):>7} responses")
    print(f"\nSaved {config.EXTRACTED_CSV}")


if __name__ == "__main__":
    main()
