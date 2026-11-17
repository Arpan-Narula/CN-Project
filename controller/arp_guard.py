import os
import struct
import sys

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import udp
from ryu.lib.packet import dhcp
from ryu.lib import hub

try:
    from controller.binding_table import BindingTable
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from binding_table import BindingTable

DEFAULT_TRUSTED_PORTS = {1: {4}}

QUARANTINE_SECONDS = 60
LEASE_SECONDS = 3600
GC_INTERVAL_SECONDS = 10

PRIO_TABLE_MISS = 0
PRIO_FORWARD = 10
PRIO_INSPECT = 20
PRIO_ROGUE_DHCP = 90
PRIO_QUARANTINE = 100

ARP_METER_ID = 1
ARP_METER_RATE_PPS = 200
ARP_METER_BURST = 100

DHCP_ACK = 5


def _load_trusted_ports():
    env = os.environ.get("ARP_GUARD_TRUSTED")
    if not env:
        return {k: set(v) for k, v in DEFAULT_TRUSTED_PORTS.items()}
    trusted = {}
    for item in env.split(","):
        dpid, port = item.strip().split(":")
        trusted.setdefault(int(dpid, 0), set()).add(int(port))
    return trusted


def _is_multicast(mac):
    return int(mac.split(":")[0], 16) & 1 == 1


class ArpGuard(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ArpGuard, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.trusted_ports = _load_trusted_ports()
        self.use_meter = os.environ.get("ARP_GUARD_METER", "1") != "0"
        self.binding_table = BindingTable(
            default_lease_seconds=LEASE_SECONDS,
            quarantine_seconds=QUARANTINE_SECONDS,
        )
        self.datapaths = {}
        self.gc_thread = hub.spawn(self._gc_loop)
        self.logger.info("Trusted DHCP ports: %s | ARP meter: %s",
                         self.trusted_ports, self.use_meter)

    def _gc_loop(self):
        while True:
            hub.sleep(GC_INTERVAL_SECONDS)
            removed = self.binding_table.remove_expired()
            if removed:
                self.logger.info("[GC] Expired %d lease(s): %s", len(removed), removed)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        to_ctrl = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]

        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=ofproto.OFPTT_ALL,
            command=ofproto.OFPFC_DELETE, out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY, match=parser.OFPMatch()))

        self.add_flow(datapath, PRIO_TABLE_MISS, parser.OFPMatch(), to_ctrl)

        meter_id = None
        if self.use_meter:
            self._install_arp_meter(datapath)
            meter_id = ARP_METER_ID
        self.add_flow(datapath, PRIO_INSPECT,
                      parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP),
                      to_ctrl, meter_id=meter_id)

        for field in ("udp_src", "udp_dst"):
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP,
                                    ip_proto=in_proto.IPPROTO_UDP,
                                    **{field: 67})
            self.add_flow(datapath, PRIO_INSPECT, match, to_ctrl)

        self.logger.info("Switch %s connected; pipeline installed.", datapath.id)

    def _install_arp_meter(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPMeterMod(
            datapath=datapath, command=ofproto.OFPMC_DELETE,
            flags=0, meter_id=ARP_METER_ID))
        bands = [parser.OFPMeterBandDrop(rate=ARP_METER_RATE_PPS,
                                         burst_size=ARP_METER_BURST)]
        datapath.send_msg(parser.OFPMeterMod(
            datapath=datapath, command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_PKTPS, meter_id=ARP_METER_ID, bands=bands))

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_handler(self, ev):
        msg = ev.msg
        self.logger.error("OpenFlow error type=0x%02x code=0x%02x (if this is a "
                          "meter error, restart with ARP_GUARD_METER=0)",
                          msg.type, msg.code)

    def add_flow(self, datapath, priority, match, actions,
                 hard_timeout=0, idle_timeout=0, meter_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = []
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))
        inst.append(parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions))
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, hard_timeout=hard_timeout,
            idle_timeout=idle_timeout))

    def install_drop_flow(self, datapath, mac, port, hard_timeout=QUARANTINE_SECONDS):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=port, eth_src=mac)
        self.add_flow(datapath, PRIO_QUARANTINE, match, [],
                      hard_timeout=hard_timeout)
        self.binding_table.quarantine(mac, port, hard_timeout)
        self.logger.warning("[QUARANTINE] dpid=%s mac=%s port=%s for %ss",
                            datapath.id, mac, port, hard_timeout)

    def install_rogue_dhcp_drop(self, datapath, port, hard_timeout=QUARANTINE_SECONDS):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=port, eth_type=ether_types.ETH_TYPE_IP,
                                ip_proto=in_proto.IPPROTO_UDP, udp_src=67)
        self.add_flow(datapath, PRIO_ROGUE_DHCP, match, [], hard_timeout=hard_timeout)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return

        if self.binding_table.is_quarantined(eth.src, in_port):
            return

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            self._handle_arp(datapath, in_port, pkt, eth, msg)
            return

        if eth.ethertype == ether_types.ETH_TYPE_IP:
            udp_hdr = pkt.get_protocol(udp.udp)
            if udp_hdr is not None and udp_hdr.src_port == 67:
                if not self._handle_dhcp(datapath, in_port, pkt, eth):
                    return

        self._l2_forward(datapath, in_port, eth, msg)

    def _handle_dhcp(self, datapath, in_port, pkt, eth):
        dpid = datapath.id
        dhcp_pkt = pkt.get_protocol(dhcp.dhcp)
        if dhcp_pkt is None:
            return True

        if in_port not in self.trusted_ports.get(dpid, set()):
            self.logger.error(
                "[ROGUE-DHCP] DHCP server reply from %s on UNTRUSTED dpid=%s port=%s "
                "- dropping.", eth.src, dpid, in_port)
            self.install_rogue_dhcp_drop(datapath, in_port)
            return False

        msg_type, lease_time = None, None
        for opt in (dhcp_pkt.options.option_list if dhcp_pkt.options else []):
            if not isinstance(opt.value, (bytes, bytearray)):
                continue
            if opt.tag == 53 and len(opt.value) >= 1:
                msg_type = opt.value[0]
            elif opt.tag == 51 and len(opt.value) == 4:
                lease_time = struct.unpack("!I", bytes(opt.value))[0]

        yiaddr, chaddr = dhcp_pkt.yiaddr, dhcp_pkt.chaddr
        if msg_type == DHCP_ACK and yiaddr and yiaddr != "0.0.0.0":
            # binding uses the client's learned port, not the ACK's in_port
            client_port = self.mac_to_port.get(dpid, {}).get(chaddr.lower())
            lease = self.binding_table.add_lease(yiaddr, chaddr, client_port,
                                                 lease_seconds=lease_time)
            self.logger.info(
                "[DHCP-SNOOP] Learned binding: %s -> mac=%s port=%s (expires %.0f)",
                yiaddr, chaddr, client_port, lease.expiry)
        return True

    def _handle_arp(self, datapath, in_port, pkt, eth, msg):
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is None:
            return

        dpid = datapath.id
        sender_ip, sender_mac = arp_pkt.src_ip, arp_pkt.src_mac

        if in_port in self.trusted_ports.get(dpid, set()):
            self._learn(dpid, eth.src, in_port)
            self._forward_arp(datapath, in_port, eth, msg)
            return

        consistent = eth.src.lower() == sender_mac.lower()
        if consistent and sender_ip == "0.0.0.0":
            valid = True
        else:
            valid = consistent and self.binding_table.verify_packet(
                sender_ip, sender_mac, in_port)

        if valid:
            self._learn(dpid, eth.src, in_port)
            self._forward_arp(datapath, in_port, eth, msg)
            return

        self.logger.error(
            "[ARP-SPOOF DETECTED] dpid=%s port=%s eth_src=%s claims ip=%s mac=%s "
            "- does not match binding table (%s). Dropping & quarantining.",
            dpid, in_port, eth.src, sender_ip, sender_mac,
            self.binding_table.get_lease(sender_ip))
        self.install_drop_flow(datapath, eth.src, in_port)

    def _learn(self, dpid, mac, port):
        if _is_multicast(mac):
            return
        for lease in self.binding_table.find_by_mac(mac):
            if lease.port is not None and lease.port != port:
                return
        self.mac_to_port.setdefault(dpid, {})[mac.lower()] = port

    def _packet_out(self, datapath, msg, in_port, out_port):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=[parser.OFPActionOutput(out_port)],
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None))

    def _forward_arp(self, datapath, in_port, eth, msg):
        ofproto = datapath.ofproto
        out_port = self.mac_to_port.get(datapath.id, {}).get(
            eth.dst.lower(), ofproto.OFPP_FLOOD)
        self._packet_out(datapath, msg, in_port, out_port)

    def _l2_forward(self, datapath, in_port, eth, msg):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        self._learn(dpid, eth.src, in_port)

        out_port = self.mac_to_port.get(dpid, {}).get(eth.dst.lower(), ofproto.OFPP_FLOOD)

        if out_port != ofproto.OFPP_FLOOD and eth.ethertype == ether_types.ETH_TYPE_IP:
            match = parser.OFPMatch(in_port=in_port, eth_type=ether_types.ETH_TYPE_IP,
                                    eth_dst=eth.dst, eth_src=eth.src)
            self.add_flow(datapath, PRIO_FORWARD, match,
                          [parser.OFPActionOutput(out_port)], idle_timeout=30)

        self._packet_out(datapath, msg, in_port, out_port)
