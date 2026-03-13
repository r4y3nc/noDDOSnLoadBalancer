from __future__ import print_function


class TrafficSteering(object):
    """
    Menentukan server tujuan berdasarkan tipe protokol/port.

    Aturan:
      - Port 80  -> Round Robin via balancer (web publik)
      - Port 22  -> Paksa ke server pertama (SSH)
      - ICMP     -> Paksa ke server kedua (ping)
      - Lainnya  -> Round Robin via balancer
    """

    def __init__(self, balancer, logger=None):
        self.balancer = balancer
        self.logger   = logger

    def resolve(self, tcp_pkt, icmp_pkt):
        """
        Tentukan IP server tujuan berdasarkan isi paket.
        Kembalikan server_ip (string).
        """
        if tcp_pkt and tcp_pkt.dst_port == 80:
            server_ip = self.balancer.pilih_server()
            if self.logger:
                self.logger.info(
                    "[LOAD BALANCER] Trafik Web (port 80) diarahkan ke %s", server_ip
                )

        elif tcp_pkt and tcp_pkt.dst_port == 22:
            server_ip = self.balancer.server_list[0]
            if self.logger:
                self.logger.info(
                    "[TRAFFIC STEERING] Trafik SSH (port 22) dipaksa ke %s", server_ip
                )

        elif icmp_pkt:
            server_ip = self.balancer.server_list[1]
            if self.logger:
                self.logger.info(
                    "[TRAFFIC STEERING] Paket ICMP dipaksa ke %s", server_ip
                )

        else:
            server_ip = self.balancer.pilih_server()
            if self.logger:
                self.logger.info(
                    "[LOAD BALANCER] Trafik lain diarahkan ke %s", server_ip
                )

        return server_ip