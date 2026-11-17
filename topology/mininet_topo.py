#!/usr/bin/env python3
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink


HOST_MACS = {
    "h1": "00:00:00:00:00:01",
    "h2": "00:00:00:00:00:02",
    "h3": "00:00:00:00:00:03",
    "h_dhcp": "00:00:00:00:00:0a",
}


def build_topology():
    net = Mininet(
        controller=None,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=False,
    )

    info("*** Adding remote controller (expects Ryu at 127.0.0.1:6653)\n")
    c0 = net.addController(
        "c0",
        controller=RemoteController,
        ip="127.0.0.1",
        port=6653,
    )

    info("*** Adding switch s1 (OpenFlow 1.3)\n")
    s1 = net.addSwitch("s1", protocols="OpenFlow13")

    info("*** Adding hosts (no IPs assigned — DHCP will supply them)\n")
    h1 = net.addHost("h1", ip=None, mac=HOST_MACS["h1"])
    h2 = net.addHost("h2", ip=None, mac=HOST_MACS["h2"])
    h3 = net.addHost("h3", ip=None, mac=HOST_MACS["h3"])
    h_dhcp = net.addHost("h_dhcp", ip="10.0.0.254/24", mac=HOST_MACS["h_dhcp"])

    info("*** Creating links (port numbers matter — must match TRUSTED_PORTS "
         "in controller/arp_guard.py)\n")
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
    net.addLink(h_dhcp, s1)

    info("*** Starting network\n")
    net.start()

    info("*** Network is up.\n")
    info("    h1=%s h2=%s h3=%s(attacker) h_dhcp=%s(10.0.0.254, trusted port 4)\n" % (
        h1.name, h2.name, h3.name, h_dhcp.name
    ))
    info("*** Suggested test sequence (inside the Mininet CLI):\n")
    info("      h_dhcp dnsmasq --interface=h_dhcp-eth0 --bind-interfaces --port=0 "
         "--dhcp-range=10.0.0.50,10.0.0.200,12h --pid-file=/tmp/dnsmasq.pid "
         "--dhcp-leasefile=/tmp/dnsmasq.leases --no-daemon &\n")
    info("      h1 dhclient -v -pf /tmp/dhc-h1.pid -lf /tmp/dhc-h1.lease h1-eth0\n")
    info("      h2 dhclient -v -pf /tmp/dhc-h2.pid -lf /tmp/dhc-h2.lease h2-eth0\n")
    info("      h3 dhclient -v -pf /tmp/dhc-h3.pid -lf /tmp/dhc-h3.lease h3-eth0\n")
    info("      xterm h3\n")
    info("      (inside h3's xterm) arpspoof -i h3-eth0 -t <h1_ip> <h2_ip>\n")

    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    build_topology()
