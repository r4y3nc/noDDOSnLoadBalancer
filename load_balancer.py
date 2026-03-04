# =========================================================
# SDN FIREWALL + LOAD BALANCER
# Deteksi sederhana serangan DDoS
# =========================================================

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4

import time


class SDNFirewallLoadBalancer(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # ================================
    # KONFIGURASI LOAD BALANCER
    # ================================

    VIP = "10.0.0.100"

    LB_MAC = "aa:bb:cc:dd:ee:ff"

    SERVER_POOL = {
        "10.0.0.2": "00:00:00:00:00:02",
        "10.0.0.3": "00:00:00:00:00:03"
    }

    # ================================
    # KONFIGURASI FIREWALL
    # ================================

    REQUEST_LIMIT = 10
    TIME_WINDOW = 5
    BLOCK_TIME = 20

    # ================================
    # INISIALISASI
    # ================================

    def __init__(self, *args, **kwargs):

        super(SDNFirewallLoadBalancer, self).__init__(*args, **kwargs)

        self.server_list = list(self.SERVER_POOL.keys())
        self.server_index = 0

        self.request_table = {}
        self.blacklist = {}

        self.logger.info("============================================")
        self.logger.info(" SDN FIREWALL + LOAD BALANCER DIMULAI ")
        self.logger.info(" VIP : %s", self.VIP)
        self.logger.info(" Backend Server : %s", self.server_list)
        self.logger.info(" Firewall aktif (DDoS Detection)")
        self.logger.info("============================================")

    # ================================
    # ROUND ROBIN SERVER SELECTION
    # ================================

    def pilih_server(self):

        server = self.server_list[self.server_index]

        self.server_index = (self.server_index + 1) % len(self.server_list)

        self.logger.info("LoadBalancer memilih server : %s", server)

        return server

    # ================================
    # DETEKSI DDOS
    # ================================

    def cek_ddos(self, ip):

        now = time.time()

        if ip in self.blacklist:

            if now < self.blacklist[ip]:

                return True

            else:

                del self.blacklist[ip]

        if ip not in self.request_table:

            self.request_table[ip] = []

        self.request_table[ip].append(now)

        self.request_table[ip] = [

            t for t in self.request_table[ip]
            if now - t < self.TIME_WINDOW
        ]

        if len(self.request_table[ip]) > self.REQUEST_LIMIT:

            self.blacklist[ip] = now + self.BLOCK_TIME

            self.logger.warning("!!! DDOS TERDETEKSI !!!")
            self.logger.warning("IP %s diblokir selama %s detik",
                                ip, self.BLOCK_TIME)

            return True

        return False

    # ================================
    # SWITCH CONNECT
    # ================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connect(self, ev):

        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()

        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]

        flow = parser.OFPFlowMod(datapath=datapath,
                                 priority=0,
                                 match=match,
                                 instructions=inst)

        datapath.send_msg(flow)

        self.logger.info("Switch terhubung ke controller")

    # ================================
    # PACKET MASUK
    # ================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)

        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        in_port = msg.match['in_port']

        # ============================
        # HANDLE ARP VIP
        # ============================

        if arp_pkt:

            if arp_pkt.opcode == arp.ARP_REQUEST and arp_pkt.dst_ip == self.VIP:

                self.logger.info("ARP request VIP diterima")

                reply = packet.Packet()

                reply.add_protocol(
                    ethernet.ethernet(
                        ethertype=eth.ethertype,
                        dst=eth.src,
                        src=self.LB_MAC))

                reply.add_protocol(
                    arp.arp(
                        opcode=arp.ARP_REPLY,
                        src_mac=self.LB_MAC,
                        src_ip=self.VIP,
                        dst_mac=arp_pkt.src_mac,
                        dst_ip=arp_pkt.src_ip))

                reply.serialize()

                actions = [parser.OFPActionOutput(in_port)]

                out = parser.OFPPacketOut(
                    datapath=datapath,
                    buffer_id=ofproto.OFP_NO_BUFFER,
                    in_port=ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=reply.data)

                datapath.send_msg(out)

                self.logger.info("ARP reply VIP dikirim")

                return

        # ============================
        # HANDLE TRAFFIC VIP
        # ============================

        if ip_pkt and ip_pkt.dst == self.VIP:

            src_ip = ip_pkt.src

            self.logger.info("----------------------------------")
            self.logger.info("Request dari client : %s", src_ip)

            # FIREWALL CHECK

            if self.cek_ddos(src_ip):

                self.logger.warning(
                    "Request dari %s ditolak oleh firewall", src_ip)

                return

            self.logger.info("Firewall : traffic normal")

            server_ip = self.pilih_server()

            server_mac = self.SERVER_POOL[server_ip]

            self.logger.info("LoadBalancer mengarahkan ke server %s",
                             server_ip)

            actions = [
                parser.OFPActionSetField(eth_dst=server_mac),
                parser.OFPActionOutput(2)
            ]

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data)

            datapath.send_msg(out)
