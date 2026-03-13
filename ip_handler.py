from __future__ import print_function

from ryu.lib.packet import packet as pkt_lib
from ryu.lib.packet import tcp, icmp, ipv4


class IPHandler(object):
    """
    Menangani trafik IP:
      - Klien -> VIP   : firewall + steering + NAT forward
      - Server -> Klien: NAT reverse + release koneksi ke balancer
    """

    def __init__(self, vip, lb_mac, server_pool, firewall, balancer, steering, logger=None):
        self.VIP         = vip
        self.LB_MAC      = lb_mac
        self.SERVER_POOL = server_pool
        self.firewall    = firewall
        self.balancer    = balancer
        self.steering    = steering
        self.logger      = logger

        # Mapping { (src_ip, src_port) -> server_ip } untuk tracking koneksi
        self.conn_map = {}

    def handle_forward(self, datapath, in_port, raw_data, ip_pkt):
        """
        Trafik dari klien menuju VIP.
        Return True jika paket sudah ditangani.
        """
        src_ip = ip_pkt.src

        if self.logger:
            self.logger.info("----------------------------------")
            self.logger.info("Request dari client : %s", src_ip)

        if self.firewall.cek_ddos(src_ip):
            if self.logger:
                self.logger.warning(
                    "Request dari %s ditolak oleh firewall", src_ip
                )
            return True

        if self.logger:
            self.logger.info("Firewall : traffic normal")

        parsed   = pkt_lib.Packet(raw_data)
        tcp_pkt  = parsed.get_protocol(tcp.tcp)
        icmp_pkt = parsed.get_protocol(icmp.icmp)

        server_ip   = self.steering.resolve(tcp_pkt, icmp_pkt)
        server_info = self.balancer.get_server_info(server_ip)

        # Simpan mapping koneksi agar bisa di-release saat reverse
        conn_key = (src_ip, tcp_pkt.src_port if tcp_pkt else 0)
        self.conn_map[conn_key] = server_ip

        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [
            parser.OFPActionSetField(eth_dst=server_info["mac"]),
            parser.OFPActionSetField(ipv4_dst=server_ip),
            parser.OFPActionOutput(server_info["port"]),
        ]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=raw_data,
        )
        datapath.send_msg(out)
        return True

    def handle_reverse(self, datapath, in_port, raw_data, ip_pkt):
        """
        Trafik dari server kembali ke klien, disamarkan sebagai VIP.
        Sekaligus release koneksi aktif di balancer.
        Return True jika paket sudah ditangani.
        """
        server_ip = ip_pkt.src

        # Release koneksi jika ini paket TCP FIN/RST (koneksi selesai)
        parsed  = pkt_lib.Packet(raw_data)
        tcp_pkt = parsed.get_protocol(tcp.tcp)

        if tcp_pkt and (tcp_pkt.bits & 0x01 or tcp_pkt.bits & 0x04):
            # FIN (0x01) atau RST (0x04)
            self.balancer.release(server_ip)

            # Bersihkan conn_map untuk koneksi ini
            dst_ip   = ip_pkt.dst
            conn_key = (dst_ip, tcp_pkt.dst_port)
            self.conn_map.pop(conn_key, None)

        parser  = datapath.ofproto_parser
        ofproto = datapath.ofproto

        actions = [
            parser.OFPActionSetField(eth_src=self.LB_MAC),
            parser.OFPActionSetField(ipv4_src=self.VIP),
            parser.OFPActionOutput(1),  # Klien diasumsikan selalu di port 1
        ]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=raw_data,
        )
        datapath.send_msg(out)
        return True