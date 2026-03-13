# =========================================================
# SDN FIREWALL + LOAD BALANCER
# Entry point utama
# Jalankan: cd /app && ryu-manager main.py
# =========================================================

from __future__ import print_function

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4

import config
from ddos import DDoSDetector
from balancer import LeastConnectionBalancer
from traffic_steering import TrafficSteering
from arp_handler import ARPHandler
from ip_handler import IPHandler


class SDNFirewallLoadBalancer(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFirewallLoadBalancer, self).__init__(*args, **kwargs)

        self.firewall = DDoSDetector(
            request_limit=config.REQUEST_LIMIT,
            time_window=config.TIME_WINDOW,
            block_time=config.BLOCK_TIME,
            logger=self.logger,
        )

        self.balancer = LeastConnectionBalancer(
            server_pool=config.SERVER_POOL,
            logger=self.logger,
        )

        self.steering = TrafficSteering(
            balancer=self.balancer,
            logger=self.logger,
        )

        self.arp_handler = ARPHandler(
            vip=config.VIP,
            lb_mac=config.LB_MAC,
            logger=self.logger,
        )

        self.ip_handler = IPHandler(
            vip=config.VIP,
            lb_mac=config.LB_MAC,
            server_pool=config.SERVER_POOL,
            firewall=self.firewall,
            balancer=self.balancer,
            steering=self.steering,
            logger=self.logger,
        )

        self.logger.info("============================================")
        self.logger.info(" SDN FIREWALL + LOAD BALANCER DIMULAI ")
        self.logger.info(" VIP    : %s", config.VIP)
        self.logger.info(" Server : %s", self.balancer.server_list)
        self.logger.info(" Firewall aktif (DDoS Detection)")
        self.logger.info("============================================")

    # ================================
    # SWITCH CONNECT
    # ================================

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_connect(self, ev):
        datapath = ev.msg.datapath
        parser   = datapath.ofproto_parser
        ofproto  = datapath.ofproto

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        inst    = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        flow = parser.OFPFlowMod(
            datapath=datapath, priority=0, match=match, instructions=inst
        )
        datapath.send_msg(flow)
        self.logger.info("Switch terhubung ke controller")

    # ================================
    # PACKET MASUK
    # ================================

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        pkt     = packet.Packet(msg.data)
        eth     = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)

        in_port = msg.match['in_port']

        # 1. ARP ke VIP
        if arp_pkt:
            if self.arp_handler.handle(datapath, in_port, eth, arp_pkt):
                return

        # 2. IP menuju VIP (klien -> server)
        if ip_pkt and ip_pkt.dst == config.VIP:
            self.ip_handler.handle_forward(datapath, in_port, msg.data, ip_pkt)
            return

        # 3. IP dari server (server -> klien), NAT reverse
        if ip_pkt and ip_pkt.src in config.SERVER_POOL:
            self.ip_handler.handle_reverse(datapath, in_port, msg.data, ip_pkt)
            return

        # 4. Flooding untuk ARP biasa
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=msg.data,
        )
        datapath.send_msg(out)