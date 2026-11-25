"""
get_datasets.py - download the public PCAPs used in this project into data/pcaps.
Uses only Python's standard library (no git needed). Run once:
    python get_datasets.py
Files that already exist are skipped, so it can be re-run after a broken download.

Sources
  1. Korving, F. DNS Tunnel Dataset (MIT licence), TalTech MSc thesis,
     ICCWS 2023, DOI 10.34190/iccws.18.1.962
     https://github.com/Korving-F/dns-tunnel-dataset
     -> Iodine (6 record types x 4 encodings), DNScat2, dns2tcp; BIND9 resolver.
  2. Gao et al. GraphTunnel DNS-Tunnel-Datasets, IEEE 2024
     https://github.com/ggyggy666/DNS-Tunnel-Datasets
     -> benign "top sites" traffic, benign wildcard traffic,
        Iodine in A-record mode, Cobalt Strike DNS beacon.
"""
import io
import os
import tarfile
import urllib.request

PCAP_DIR = os.path.join("data", "pcaps")

# "raw" GitHub addresses give the file itself (branch names: master / main)
KORVING_RAW = "https://raw.githubusercontent.com/Korving-F/dns-tunnel-dataset/master"
GAO_RAW = "https://raw.githubusercontent.com/ggyggy666/DNS-Tunnel-Datasets/main"

# Korving folder (one per configuration, BIND9 resolver)  ->  our file name
KORVING = [
    ("dns_tunnel_file_transfer/b6cfd110174fb553bb73a5279358c6c1", "iodine_file_transfer_CNAME_BASE64.pcap"),
    ("dns_tunnel_file_transfer/a1c38fbf7990981b871ab08197fd7f05", "iodine_file_transfer_CNAME_RAW.pcap"),
    ("dns_tunnel_file_transfer/3760552cd9b00f3d77da69a99eb92244", "iodine_file_transfer_CNAME_BASE128.pcap"),
    ("dns_tunnel_file_transfer/ddd18462596f938b37d73386b0b79cd2", "iodine_file_transfer_CNAME_BASE32.pcap"),
    ("dns_tunnel_file_transfer/bcbc96decb05ec093b77a45cd2190db2", "iodine_file_transfer_MX_BASE64.pcap"),
    ("dns_tunnel_file_transfer/54879844c9d07bb26fc85fcfb259a32b", "iodine_file_transfer_MX_BASE128.pcap"),
    ("dns_tunnel_file_transfer/4b45b468003dafc9bb3681796d4d5a58", "iodine_file_transfer_MX_RAW.pcap"),
    ("dns_tunnel_file_transfer/a022626474e70afcfa32bb412203b26d", "iodine_file_transfer_MX_BASE32.pcap"),
    ("dns_tunnel_file_transfer/443aade3193a3e68d5aded293e7256d9", "iodine_file_transfer_NULL_BASE64.pcap"),
    ("dns_tunnel_file_transfer/764c3e9ffbd006fca30854042d303e57", "iodine_file_transfer_NULL_BASE32.pcap"),
    ("dns_tunnel_file_transfer/0455ce50cb935a6dbfc73182674c9e5f", "iodine_file_transfer_NULL_BASE128.pcap"),
    ("dns_tunnel_file_transfer/3fe59915324da1ef9d9ae2fefd735fd9", "iodine_file_transfer_NULL_RAW.pcap"),
    ("dns_tunnel_file_transfer/ffd66a98ae4c6591a9884a9de258fd75", "iodine_file_transfer_PRIVATE_RAW.pcap"),
    ("dns_tunnel_file_transfer/c65ede91d1f30b627fb70e408bfef5b0", "iodine_file_transfer_PRIVATE_BASE32.pcap"),
    ("dns_tunnel_file_transfer/a99fe827bdd2c4377e314b1403b1b288", "iodine_file_transfer_PRIVATE_BASE64.pcap"),
    ("dns_tunnel_file_transfer/a17ab6a026981083dce589699692ea17", "iodine_file_transfer_PRIVATE_BASE128.pcap"),
    ("dns_tunnel_file_transfer/c94056fa19491662e1b3aed355b61890", "iodine_file_transfer_SRV_BASE32.pcap"),
    ("dns_tunnel_file_transfer/0be4e57778899c15d5ffdf65992219df", "iodine_file_transfer_SRV_RAW.pcap"),
    ("dns_tunnel_file_transfer/22d227233839a9c998979247185163fb", "iodine_file_transfer_SRV_BASE64.pcap"),
    ("dns_tunnel_file_transfer/de6d5b30160e86c4857bd90471ee931b", "iodine_file_transfer_SRV_BASE128.pcap"),
    ("dns_tunnel_file_transfer/86950175ba9bf6b4aaea5478bbd49ad7", "iodine_file_transfer_TXT_BASE32.pcap"),
    ("dns_tunnel_file_transfer/c6a08caf0d52af99dfd2487f2b48c54a", "iodine_file_transfer_TXT_BASE64.pcap"),
    ("dns_tunnel_file_transfer/7e2db7516bcc8a31c68e8f3ef057c461", "iodine_file_transfer_TXT_BASE128.pcap"),
    ("dns_tunnel_file_transfer/abbffe6c1c7075d378a42c9a73fba0df", "iodine_file_transfer_TXT_RAW.pcap"),
    ("dns_tunnel_file_transfer/d38bd4d0f4519ed3a19169f3b5420fec", "dns2tcp_file_transfer_KEY_YES.pcap"),
    ("dns_tunnel_file_transfer/e42ff3f6df0dcf6f67ceff5389b27ac5", "dns2tcp_file_transfer_KEY_NO.pcap"),
    ("dns_tunnel_file_transfer/1859482d263a4a0e80b8930fe956ddfc", "dns2tcp_file_transfer_TXT_YES.pcap"),
    ("dns_tunnel_file_transfer/78e4e15ea053492cd7543b3e3ad1982d", "dns2tcp_file_transfer_TXT_NO.pcap"),
    ("dns_tunnel_file_transfer/8c2ef973a2d27a2c4581f347aa196b5b", "dnscat_file_transfer_TXT-CNAME-MX_default.pcap"),
    ("dns_tunnel_c2/55db4c68c292a14ff92dd9f5fb712b01", "dns2tcp_c2_KEY_NO.pcap"),
    ("dns_tunnel_c2/833c16e0c082100518d4a3a200b822c2", "dns2tcp_c2_KEY_YES.pcap"),
    ("dns_tunnel_c2/6892133f5e90a52a915ffb0952ac621e", "dns2tcp_c2_TXT_YES.pcap"),
    ("dns_tunnel_c2/af88c701c4dea95b51e33748eafb76ab", "dns2tcp_c2_TXT_NO.pcap"),
    ("dns_tunnel_c2/8c2ef973a2d27a2c4581f347aa196b5b", "dnscat_c2_TXT-CNAME-MX_default.pcap"),
]

# Gao file  ->  our file name
GAO = [(f"normal/normal/{n}", f"benign_gao_{n.split('/')[-1]}") for n in [
    "normal_00000_20230805150331.pcap", "normal_00001_20230805152732.pcap",
    "normal_00002_20230805155315.pcap", "normal_00003_20230805162300.pcap",
    "normal_00004_20230805165638.pcap", "normal_00005_20230805173251.pcap"]]
GAO += [(f"wildcard/{n}", f"benign_gao_{n}") for n in [
    "wildcard_00000_20231011215521.pcap", "wildcard_00001_20231011215715.pcap",
    "wildcard_00002_20231011220330.pcap", "wildcard_00003_20231011220812.pcap"]]
GAO += [("tunnel/iodine-a.pcap", "gao_iodine_A.pcap"),
        ("unkownTunnel/cobalstrike.pcap", "gao_cobaltstrike.pcap")]


def download(url):
    """Download a file from the internet and return its bytes."""
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def main():
    os.makedirs(PCAP_DIR, exist_ok=True)

    print("Korving dataset (Iodine, DNScat2, dns2tcp):")
    for folder, out_name in KORVING:
        out_path = os.path.join(PCAP_DIR, out_name)
        if os.path.exists(out_path):
            print("   already there:", out_name)
            continue
        config_id = folder.split("/")[-1]
        archive = download(f"{KORVING_RAW}/{folder}/{config_id}_full_dataset.tar.gz")
        # each archive holds captures from several DNS servers; we take BIND9's
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            pcap = tar.extractfile(f"{config_id}/bind9/dns.pcap").read()
        with open(out_path, "wb") as f:
            f.write(pcap)
        print("  ", out_name)

    print("Gao GraphTunnel dataset (benign, Iodine A-mode, Cobalt Strike):")
    for path, out_name in GAO:
        out_path = os.path.join(PCAP_DIR, out_name)
        if os.path.exists(out_path):
            print("   already there:", out_name)
            continue
        with open(out_path, "wb") as f:
            f.write(download(f"{GAO_RAW}/{path}"))
        print("  ", out_name)

    print(f"\nDone. PCAPs are in {PCAP_DIR}.")


if __name__ == "__main__":
    main()
