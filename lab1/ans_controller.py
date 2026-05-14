"""
 Copyright (c) 2026 Computer Networks Group @ UPB
 
 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:
 
 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """
 
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, icmp, tcp, udp
import struct
import socket
 
 
# ===========================================================================
#  Topology constants  (the controller is allowed to know these per the lab)
# ===========================================================================
 
ROUTER_DPID = 3   # s3 is the router datapath
 
# Router MAC address for each of its ports
PORT_TO_OWN_MAC = {
    1: '00:00:00:00:01:01',   # port facing s1  / subnet 10.0.1.0/24
    2: '00:00:00:00:01:02',   # port facing s2  / subnet 10.0.2.0/24
    3: '00:00:00:00:01:03',   # port facing ext / subnet 192.168.1.0/24
}
 
# Router IP address for each of its ports (the gateway IPs)
PORT_TO_OWN_IP = {
    1: '10.0.1.1',
    2: '10.0.2.1',
    3: '192.168.1.1',
}
 
# Subnet CIDR -> which router port leads there
SUBNETS = {
    ('10.0.1.0',   24): 1,
    ('10.0.2.0',   24): 2,
    ('192.168.1.0', 24): 3,
}
 
# Security constants
EXTERNAL_NET   = ('192.168.1.0', 24)   # ext subnet
INTERNAL_SER_IP = '10.0.2.2'           # ser's IP
 
 
# ===========================================================================
#  Small helper functions
# ===========================================================================
 
def ip_to_int(ip_str):
    return struct.unpack('!I', socket.inet_aton(ip_str))[0]
 
def ip_in_subnet(ip_str, net_str, prefix_len):
    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    return (ip_to_int(ip_str) & mask) == (ip_to_int(net_str) & mask)
 
def get_egress_port(dst_ip):
    """Return the router port number that leads toward dst_ip, or None."""
    for (net, plen), port in SUBNETS.items():
        if ip_in_subnet(dst_ip, net, plen):
            return port
    return None
 
def is_external(ip_str):
    net, plen = EXTERNAL_NET
    return ip_in_subnet(ip_str, net, plen)
 
 
# ===========================================================================
#  Ryu Controller Application
# ===========================================================================
 
class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
 
    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
 
        # MAC learning table for switches  {dpid: {mac: port}}
        self.mac_table = {}
 
        # ARP cache for the router  {ip_str: mac_str}
        self.arp_cache = {}
 
        # Packets waiting for ARP resolution  {ip_str: [(datapath, in_port, pkt, eth, ip4)]}
        self.pending = {}
 
    # -----------------------------------------------------------------------
    #  OpenFlow setup: install table-miss rule on every switch that connects
    # -----------------------------------------------------------------------
 
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
 
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
 
        # Initial flow entry for matching misses
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info('Switch %s connected', datapath.id)
 
    # -----------------------------------------------------------------------
    #  Add a flow entry to the flow-table
    # -----------------------------------------------------------------------
 
    def add_flow(self, datapath, priority, match, actions, idle=0, hard=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
 
        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle, hard_timeout=hard)
        datapath.send_msg(mod)
 
    # -----------------------------------------------------------------------
    #  Handle the packet_in event
    # -----------------------------------------------------------------------
 
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
 
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match['in_port']
 
        pkt = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return
 
        # Dispatch to switch logic or router logic based on datapath id
        if dpid == ROUTER_DPID:
            self._handle_router(datapath, in_port, pkt, eth_pkt, msg)
        else:
            self._handle_switch(datapath, in_port, pkt, eth_pkt, msg)
 
    # =======================================================================
    #  SWITCH LOGIC  (used by s1 and s2)
    # =======================================================================
 
    def _handle_switch(self, datapath, in_port, pkt, eth_pkt, msg):
        """
        Standard MAC-learning switch:
          1. Learn src MAC -> in_port mapping.
          2. If dst MAC is already known, install a flow rule and forward.
          3. Otherwise flood out all ports.
 
        We match on (in_port, eth_dst) so that the rule is unambiguous even
        when the same MAC is reachable on different ports at different times.
        """
        dpid    = datapath.id
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
 
        src_mac = eth_pkt.src
        dst_mac = eth_pkt.dst
 
        if dpid not in self.mac_table:
            self.mac_table[dpid] = {}
 
        # Learn the source
        self.mac_table[dpid][src_mac] = in_port
        self.logger.info('Switch %s learned %s on port %s', dpid, src_mac, in_port)
 
        if dst_mac in self.mac_table[dpid]:
            out_port = self.mac_table[dpid][dst_mac]
 
            # Install flow rule: (in_port, eth_dst) -> output(out_port)
            match   = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 10, match, actions, idle=30)
 
            # Forward this specific packet too
            data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
            out  = parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id,
                in_port=in_port, actions=actions, data=data)
            datapath.send_msg(out)
        else:
            # Destination unknown -> flood
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port, actions=actions, data=msg.data)
            datapath.send_msg(out)
 
    # =======================================================================
    #  ROUTER LOGIC  (used by s3)
    # =======================================================================
 
    def _handle_router(self, datapath, in_port, pkt, eth_pkt, msg):
        """Dispatch ARP or IPv4 packets to the appropriate handler."""
        arp_pkt  = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
 
        if arp_pkt:
            self._handle_arp(datapath, in_port, pkt, eth_pkt, arp_pkt)
        elif ipv4_pkt:
            self._handle_ipv4(datapath, in_port, pkt, eth_pkt, ipv4_pkt, msg)
 
    # -------------------------------------------------------------------
    #  ARP  (router acts as ARP proxy for its own IPs)
    # -------------------------------------------------------------------
 
    def _handle_arp(self, datapath, in_port, pkt, eth_pkt, arp_pkt):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
 
        src_ip  = arp_pkt.src_ip
        dst_ip  = arp_pkt.dst_ip
        src_mac = arp_pkt.src_mac
 
        # Always cache the sender
        self.arp_cache[src_ip] = src_mac
        self.logger.info('Router ARP cache: %s -> %s', src_ip, src_mac)
 
        if arp_pkt.opcode == arp.ARP_REQUEST:
            # Check if the target IP is one of our own gateway IPs
            own_mac = None
            for port, gw_ip in PORT_TO_OWN_IP.items():
                if gw_ip == dst_ip:
                    own_mac = PORT_TO_OWN_MAC[port]
                    break
 
            if own_mac is None:
                return  # Not for us, ignore
 
            # Build and send ARP reply
            reply = packet.Packet()
            reply.add_protocol(ethernet.ethernet(
                dst=src_mac, src=own_mac, ethertype=0x0806))
            reply.add_protocol(arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=own_mac, src_ip=dst_ip,
                dst_mac=src_mac, dst_ip=src_ip))
            reply.serialize()
 
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(
                datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER, actions=actions,
                data=reply.data)
            datapath.send_msg(out)
            self.logger.info('ARP reply sent: %s is at %s', dst_ip, own_mac)
 
        elif arp_pkt.opcode == arp.ARP_REPLY:
            # Flush any packets that were waiting for this MAC
            if src_ip in self.pending:
                for (dp, iport, saved_pkt, saved_eth, saved_ip4) in self.pending.pop(src_ip):
                    self._forward_ipv4(dp, iport, saved_pkt, saved_eth, saved_ip4)
 
    # -------------------------------------------------------------------
    #  IPv4 routing
    # -------------------------------------------------------------------
 
    def _handle_ipv4(self, datapath, in_port, pkt, eth_pkt, ipv4_pkt, msg):
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        proto  = ipv4_pkt.proto   # 1=ICMP, 6=TCP, 17=UDP
 
        # ── Security rule 1 ─────────────────────────────────────────────
        # ext cannot PING (ICMP) any internal host
        if is_external(src_ip) and not is_external(dst_ip):
            if proto == 1:  # ICMP
                self.logger.info('BLOCK ICMP ext->internal: %s->%s', src_ip, dst_ip)
                self._install_drop(datapath, src_ip, dst_ip, ip_proto=1)
                return
 
        # ── Security rule 2 ─────────────────────────────────────────────
        # TCP/UDP between ext and ser is forbidden (both directions)
        if ((is_external(src_ip) and dst_ip == INTERNAL_SER_IP) or
                (src_ip == INTERNAL_SER_IP and is_external(dst_ip))):
            if proto in (6, 17):  # TCP or UDP
                self.logger.info('BLOCK TCP/UDP ext<->ser: %s<->%s', src_ip, dst_ip)
                self._install_drop(datapath, src_ip, dst_ip, ip_proto=proto)
                return
 
        # ── Packet destined for one of the router's own IPs (gateway ping) ──
        for port, gw_ip in PORT_TO_OWN_IP.items():
            if dst_ip == gw_ip:
                icmp_pkt = pkt.get_protocol(icmp.icmp)
                if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                    # Only reply if the packet came in on the matching port
                    if port == in_port:
                        self._send_icmp_reply(datapath, in_port, eth_pkt, ipv4_pkt, icmp_pkt)
                # Either way, do not forward further
                return
 
        # ── Normal inter-subnet routing ──────────────────────────────────
        self._forward_ipv4(datapath, in_port, pkt, eth_pkt, ipv4_pkt)
 
    def _forward_ipv4(self, datapath, in_port, pkt, eth_pkt, ipv4_pkt):
        """Resolve ARP if needed, then forward the packet to the correct port."""
        dst_ip = ipv4_pkt.dst
        src_ip = ipv4_pkt.src
        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto
 
        egress_port = get_egress_port(dst_ip)
        if egress_port is None:
            self.logger.warning('No route to %s, dropping', dst_ip)
            return
 
        new_src_mac = PORT_TO_OWN_MAC[egress_port]
 
        if dst_ip not in self.arp_cache:
            # Buffer the packet and send an ARP request
            if dst_ip not in self.pending:
                self.pending[dst_ip] = []
            self.pending[dst_ip].append((datapath, in_port, pkt, eth_pkt, ipv4_pkt))
            self._send_arp_request(datapath, egress_port, dst_ip)
            return
 
        new_dst_mac = self.arp_cache[dst_ip]
 
        # Install a flow rule so future packets bypass the controller
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
        actions = [
            parser.OFPActionSetField(eth_src=new_src_mac),
            parser.OFPActionSetField(eth_dst=new_dst_mac),
            parser.OFPActionDecNwTtl(),
            parser.OFPActionOutput(egress_port),
        ]
        self.add_flow(datapath, 20, match, actions, idle=60)
 
        # Forward the current packet immediately
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port, actions=actions, data=pkt.data)
        datapath.send_msg(out)
        self.logger.info('Route %s -> %s via port %d', src_ip, dst_ip, egress_port)
 
    # -------------------------------------------------------------------
    #  ARP request sent by the router itself
    # -------------------------------------------------------------------
 
    def _send_arp_request(self, datapath, out_port, target_ip):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
 
        src_mac = PORT_TO_OWN_MAC[out_port]
        src_ip  = PORT_TO_OWN_IP[out_port]
 
        req = packet.Packet()
        req.add_protocol(ethernet.ethernet(
            dst='ff:ff:ff:ff:ff:ff', src=src_mac, ethertype=0x0806))
        req.add_protocol(arp.arp(
            opcode=arp.ARP_REQUEST,
            src_mac=src_mac, src_ip=src_ip,
            dst_mac='00:00:00:00:00:00', dst_ip=target_ip))
        req.serialize()
 
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=req.data)
        datapath.send_msg(out)
        self.logger.info('ARP request sent: who has %s?', target_ip)
 
    # -------------------------------------------------------------------
    #  ICMP echo reply (so hosts can ping their own gateway)
    # -------------------------------------------------------------------
 
    def _send_icmp_reply(self, datapath, in_port, eth_pkt, ipv4_pkt, icmp_pkt):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser
 
        # The gateway IP/MAC for the port the request came in on
        my_ip  = PORT_TO_OWN_IP[in_port]
        my_mac = PORT_TO_OWN_MAC[in_port]
 
        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            dst=eth_pkt.src, src=my_mac, ethertype=0x0800))
        reply.add_protocol(ipv4.ipv4(
            src=my_ip, dst=ipv4_pkt.src, proto=1, ttl=64))
        reply.add_protocol(icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY, code=0, csum=0,
            data=icmp_pkt.data))
        reply.serialize()
 
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER, actions=actions,
            data=reply.data)
        datapath.send_msg(out)
        self.logger.info('ICMP reply: %s -> %s', my_ip, ipv4_pkt.src)
 
    # -------------------------------------------------------------------
    #  Install a drop rule (empty action list = drop)
    # -------------------------------------------------------------------
 
    def _install_drop(self, datapath, src_ip, dst_ip, ip_proto=None):
        parser = datapath.ofproto_parser
        if ip_proto is not None:
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=src_ip, ipv4_dst=dst_ip,
                ip_proto=ip_proto)
        else:
            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_src=src_ip, ipv4_dst=dst_ip)
        self.add_flow(datapath, 30, match, [], idle=120)