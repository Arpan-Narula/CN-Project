# SDN Dynamic ARP Guard

An open-source Dynamic ARP Inspection (DAI) system built on Mininet + Ryu
(OpenFlow 1.3) + Open vSwitch. It replaces proprietary switch-firmware DAI
with a programmable SDN control plane: the controller learns trusted
IP↔MAC↔port bindings from DHCP traffic, then inspects every ARP packet
against that table and drops/quarantines mismatches (ARP spoofing /
cache-poisoning attempts) at line rate.

```
sdn_arp_guard/
├── controller/
│   ├── __init__.py
│   ├── arp_guard.py         # Main Ryu OpenFlow app (DHCP snooping + DAI)
│   └── binding_table.py     # IP-MAC-Port lease data structure
├── topology/
│   └── mininet_topo.py      # 4-host Mininet topology
└── scripts/
    ├── attacker.py          # Scapy forged-ARP generator
    └── setup_rpi_ovs.sh     # Physical OVS bridge setup for Raspberry Pi
```

---

## 0. Important platform note

Mininet **requires Linux** (it creates network namespaces directly on the
kernel). It does **not** run on native Windows or macOS.

- **If your laptop runs Windows:** install **WSL2 with Ubuntu**. Everything
  below is run inside that Ubuntu environment.
- **If your laptop runs Linux already:** skip straight to step 2.
- **If your laptop runs macOS:** easiest path is a free Ubuntu VM in
  VirtualBox/UTM, or a cloud Ubuntu VM. (WSL2 doesn't exist on macOS.)

---

## 1. Install WSL2 + Ubuntu (Windows users only)

Open **PowerShell as Administrator** and run:

```powershell
wsl --install -d Ubuntu-22.04
```

This installs WSL2 and Ubuntu 22.04. Reboot if prompted. After reboot, Ubuntu
launches automatically and asks you to create a Linux username/password —
do that, then you have a terminal.

From now on, every command in this guide runs **inside that Ubuntu
terminal** (search "Ubuntu" in the Start Menu to reopen it later).

---

## 2. Install all required software (one-time setup)

Inside your Ubuntu/WSL2 terminal:

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch tshark dsniff python3-pip git xterm
pip3 install ryu scapy
```

What each package is for:

| Package                 | Purpose                                              |
|--------------------------|-------------------------------------------------------|
| `mininet`                | Network emulator — creates the virtual hosts/switch   |
| `openvswitch-switch`     | The OpenFlow-capable virtual switch (data plane)       |
| `tshark`                 | Packet capture/inspection (optional, for debugging)    |
| `dsniff`                 | Provides the `arpspoof` attack tool                    |
| `python3-pip`            | Python package installer                               |
| `xterm`                  | Lets Mininet pop up a separate terminal per host       |
| `ryu` (pip)              | The SDN controller framework (Python 3, OpenFlow 1.3)  |
| `scapy` (pip)            | Python packet-crafting library (used by `attacker.py`) |

Verify Open vSwitch is running:

```bash
sudo systemctl status openvswitch-switch
```

You should see `active (running)`. Press `q` to exit the status view.

Verify Ryu installed correctly:

```bash
ryu-manager --version
```

If this prints a version number, you're ready. If it fails with an
import error (this can happen with very new `setuptools`/`eventlet`
versions), run:

```bash
pip3 install "eventlet==0.30.2" "setuptools<58"
```

then try `ryu-manager --version` again.

---

## 3. Get the project files

If you received this as a folder already, just `cd` into it:

```bash
cd sdn_arp_guard
```

(If these files live on your Windows filesystem, e.g. under
`/mnt/c/Users/<you>/...`, it's faster and more reliable to copy the
folder into your Linux home directory first:

```bash
cp -r /mnt/c/Users/<you>/path/to/sdn_arp_guard ~/sdn_arp_guard
cd ~/sdn_arp_guard
```

)

---

## 4. Compile / syntax-check (optional but recommended)

There's nothing to "compile" in the C/Java sense — this is pure Python —
but you can byte-compile and sanity-check every file in one shot:

```bash
python3 -m py_compile controller/binding_table.py controller/arp_guard.py topology/mininet_topo.py scripts/attacker.py
echo "All files compiled without syntax errors."
```

You can also run the binding table's built-in self-test on its own,
with no Mininet/Ryu needed:

```bash
python3 controller/binding_table.py
```

Expected output ends with `All binding_table.py smoke tests passed.`

---

## 5. Run the full simulation (3 terminals)

Open **three separate Ubuntu/WSL2 terminal windows/tabs**, all `cd`'d
into the `sdn_arp_guard` folder.

### Terminal 1 — start the Ryu controller

```bash
cd sdn_arp_guard
ryu-manager controller/arp_guard.py
```

Leave this running. You'll watch log lines appear here as DHCP leases
are learned and as ARP spoofing attempts are detected/blocked.

### Terminal 2 — start the Mininet topology

```bash
cd sdn_arp_guard
sudo python3 topology/mininet_topo.py
```

This builds the switch + 4 hosts and drops you into the `mininet>`
prompt. Keep this terminal open — this **is** your Mininet CLI for the
rest of the test.

### Terminal 3 — not needed as a separate shell

Everything else happens by typing commands at the `mininet>` prompt you
already have in Terminal 2 (Mininet lets you run a command "on" a host
by prefixing the hostname). A third terminal is only useful if you want
to tail logs separately — optional.

---

## 6. Step-by-step test: DHCP + legitimate traffic

At the `mininet>` prompt (Terminal 2):

**Start a DHCP server on `h_dhcp`:**

```
mininet> h_dhcp dnsmasq --interface=h_dhcp-eth0 --bind-interfaces --port=0 --dhcp-range=10.0.0.50,10.0.0.200,12h --pid-file=/tmp/dnsmasq.pid --dhcp-leasefile=/tmp/dnsmasq.leases --no-daemon &
```

(`h_dhcp` is given the static address `10.0.0.254/24` by the topology
script; the clients start with no IP. `--port=0` turns off dnsmasq's DNS
half so it can't clash with anything on port 53.)

**Give `h1`, `h2` and the attacker `h3` real IP addresses via DHCP.** Each
host needs its own pid/lease file because all Mininet hosts share one
filesystem. `h3` needs a lease too, because `arpspoof` requires the
attacker to own an IP:

```
mininet> h1 dhclient -v -pf /tmp/dhc-h1.pid -lf /tmp/dhc-h1.lease h1-eth0
mininet> h2 dhclient -v -pf /tmp/dhc-h2.pid -lf /tmp/dhc-h2.lease h2-eth0
mininet> h3 dhclient -v -pf /tmp/dhc-h3.pid -lf /tmp/dhc-h3.lease h3-eth0
```

Watch **Terminal 1 (Ryu)** — you should see `[DHCP-SNOOP] Learned
binding: 10.0.0.x -> mac=... port=...` lines appear.

**Confirm they got IPs:**

```
mininet> h1 ip addr show h1-eth0
mininet> h2 ip addr show h2-eth0
```

**Confirm normal connectivity works:**

```
mininet> h1 ping -c 3 h2
```

This should succeed — legitimate ARP resolution + IP traffic flows
normally.

---

## 7. Step-by-step test: launch the ARP spoofing attack

Note `h1`'s and `h2`'s IPs from step 6 (e.g. `10.0.0.51` and `10.0.0.52`
— yours may differ).

**Open a separate terminal window for the attacker host:**

```
mininet> xterm h3
```

An xterm window pops up, already inside `h3`'s network namespace.

### Option A — using `arpspoof` (dsniff)

In the `h3` xterm:

```bash
arpspoof -i h3-eth0 -t 10.0.0.51 10.0.0.52
```

(Replace the IPs with h1's and h2's actual addresses — this tells h1
that h3 owns h2's IP.)

### Option B — using the included Scapy script

In the `h3` xterm:

```bash
cd ~/sdn_arp_guard   # or wherever you placed the project
python3 scripts/attacker.py --iface h3-eth0 --victim-ip 10.0.0.51 --spoof-ip 10.0.0.52 --count 20
```

---

## 8. Expected result

Watch **Terminal 1 (Ryu)**. Within the first forged packet, you should
see:

```
[ARP-SPOOF DETECTED] dpid=1 port=3 claims ip=10.0.0.52 mac=00:00:00:00:00:03 — does not match binding table (...). Dropping & quarantining.
[QUARANTINE] dpid=1 mac=00:00:00:00:00:03 port=3 for 60s
```

The controller has installed a `priority=100` drop rule on `s1` for
`h3`'s MAC/port, matching real DAI/port-security behavior. You can
verify the flow table directly from Terminal 2:

```
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1
```

Look for a rule with `priority=100,in_port=3,dl_src=00:00:00:00:00:03
actions=drop`.

Meanwhile, check that `h1`'s ARP cache was never poisoned:

```
mininet> h1 ip neigh show
```

`h2`'s IP should still map to `h2`'s real MAC
(`00:00:00:00:00:02`), not h3's.

---

## 8b. How the pieces map to the design

- **Proactive forwarding:** known-destination IPv4 flows are pushed to the
  switch (priority 10) so normal traffic never hits the controller. ARP and
  DHCP have priority-20 controller flows, so a cached forwarding flow can
  never let them skip inspection.
- **ARP throttling:** the ARP→controller flow goes through an OpenFlow 1.3
  meter (200 pkt/s, burst 100) so an ARP flood can't swamp Ryu. Check it
  with `sh ovs-ofctl -O OpenFlow13 dump-meters s1`. Disable with
  `ARP_GUARD_METER=0` if your datapath lacks meter support.
- **Rogue DHCP:** `h3 dnsmasq ...` on an untrusted port is dropped and a
  `udp_src=67` drop flow is installed on that port.
- **ARP probes** (sender IP `0.0.0.0`, sent by `dhclient`) are allowed as
  long as the Ethernet source matches the ARP sender MAC.

---

## 9. Shutting down

At the `mininet>` prompt:

```
mininet> exit
```

Then in Terminal 1, press `Ctrl+C` to stop Ryu.

If a previous run leaves stale virtual interfaces/namespaces behind,
clean up with:

```bash
sudo mn -c
```

---

## 10. Moving to physical Raspberry Pi hardware (optional, later stage)

Once the Mininet simulation works, you can repeat the exact same test
on real hardware for throughput/latency measurements, using 2+
Raspberry Pis (or any spare Linux boxes) as physical OVS switches/hosts.

1. Flash **Raspberry Pi OS (64-bit)** to each Pi (via Raspberry Pi
   Imager on your laptop), boot it, and SSH in.
2. Copy the project to the Pi:
   ```bash
   scp -r sdn_arp_guard pi@<pi_ip>:~/
   ```
3. On the Pi, run the provided setup script (needs your laptop's LAN
   IP, since the laptop keeps running the Ryu controller):
   ```bash
   cd ~/sdn_arp_guard/scripts
   chmod +x setup_rpi_ovs.sh
   sudo ./setup_rpi_ovs.sh <your_laptop_LAN_ip> br0 eth1 eth2
   ```
   `eth0` (the Pi's built-in port) stays as the management link to the
   controller, so only USB-Ethernet adapters (`eth1`, `eth2`, ...) go on
   the bridge. The script refuses to bridge the default-route interface.
4. The script installs Open vSwitch, creates bridge `br0` (datapath-id
   fixed to `1`), and points it at `tcp:<laptop_ip>:6653` — the same Ryu
   controller, unmodified.
5. Tell the controller which port the DHCP server is on, without editing
   code: `ARP_GUARD_TRUSTED="1:<port>" ryu-manager controller/arp_guard.py`
   (find the port with `sudo ovs-ofctl -O OpenFlow13 show br0`). If the
   Pi's OVS rejects meters, also set `ARP_GUARD_METER=0`.
6. Connect a victim host, a DHCP server host, and an attacker machine
   (e.g. a Kali Linux laptop/VM) to the Pi's remaining physical ports
   (via USB-to-Ethernet adapters, or a VLAN-trunked managed switch),
   and repeat the same DHCP + `arpspoof` test sequence from steps 6–8.

---

## Troubleshooting

- **`ryu-manager: command not found`** — `pip3`'s install location may
  not be on your `PATH`. Try `python3 -m ryu.cmd.manager
  controller/arp_guard.py` instead, or add `~/.local/bin` to `PATH`:
  `export PATH="$HOME/.local/bin:$PATH"`.
- **Mininet says "Unable to contact the remote controller"** — make
  sure Terminal 1 (`ryu-manager`) is already running *before* you
  start `mininet_topo.py` in Terminal 2.
- **`dnsmasq: failed to create listening socket... Address already in
  use`** — another dnsmasq/DHCP service is already running on the host;
  kill it with `mininet> h_dhcp pkill dnsmasq` and retry.
- **Everything seems stuck / leftover state from a previous run** —
  run `sudo mn -c` between attempts.
- **`ImportError` for `ryu.lib.packet.dhcp`** — make sure you installed
  Ryu via `pip3 install ryu` (not an ancient OS package); this module
  is part of standard Ryu.
