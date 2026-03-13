from ryu.lib.packet import packet, ethernet, arp


class ARPHandler:
    """
    Menangani ARP request ke VIP dan membalas dengan MAC load balancer.
    """

    def __init__(self, vip, lb_mac, logger=None):
        self.VIP = vip
        self.LB_MAC = lb_mac
        self.logger = logger

    def handle(self, datapath, in_port, eth, arp_pkt):
        """
        Proses ARP request yang menuju VIP.
        Return True jika paket sudah ditangani, False jika diabaikan.
        """
        if arp_pkt.opcode != arp.ARP_REQUEST or arp_pkt.dst_ip != self.VIP:
            return False

        if self.logger:
            self.logger.info("ARP request VIP diterima")

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        reply = packet.Packet()
        reply.add_protocol(
            ethernet.ethernet(
                ethertype=eth.ethertype,
                dst=eth.src,
                src=self.LB_MAC,
            )
        )
        reply.add_protocol(
            arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=self.LB_MAC,
                src_ip=self.VIP,
                dst_mac=arp_pkt.src_mac,
                dst_ip=arp_pkt.src_ip,
            )
        )
        reply.serialize()

        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=reply.data,
        )
        datapath.send_msg(out)

        if self.logger:
            self.logger.info("ARP reply VIP dikirim")

        return True