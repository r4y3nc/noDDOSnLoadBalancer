from __future__ import print_function


class LeastConnectionBalancer(object):
    """
    Load balancer dengan algoritma Least Connections.
    Memilih server dengan jumlah koneksi aktif paling sedikit.

    Koneksi dianggap selesai ketika paket reverse (server -> klien)
    melewati controller, lalu di-decrement oleh release().
    """

    def __init__(self, server_pool, logger=None):
        self.SERVER_POOL = server_pool
        self.server_list = list(server_pool.keys())
        self.logger      = logger

        # Tracking koneksi aktif per server { server_ip: int }
        self.active_connections = {ip: 0 for ip in self.server_list}

    def pilih_server(self):
        """
        Pilih server dengan koneksi aktif paling sedikit.
        Jika semua sama, pilih yang pertama di list.
        """
        server_ip = min(
            self.server_list,
            key=lambda ip: self.active_connections[ip]
        )
        self.active_connections[server_ip] += 1

        if self.logger:
            self.logger.info(
                "[LOAD BALANCER] Memilih server : %s "
                "(koneksi aktif: %s)",
                server_ip,
                self.active_connections
            )

        return server_ip

    def release(self, server_ip):
        """
        Decrement koneksi aktif ketika server selesai melayani request.
        Dipanggil dari ip_handler saat paket reverse terdeteksi.
        """
        if server_ip in self.active_connections:
            if self.active_connections[server_ip] > 0:
                self.active_connections[server_ip] -= 1

                if self.logger:
                    self.logger.info(
                        "[LOAD BALANCER] Koneksi selesai dari %s "
                        "(sisa aktif: %d)",
                        server_ip,
                        self.active_connections[server_ip]
                    )

    def get_server_info(self, server_ip):
        """Kembalikan dict { mac, port } untuk IP server tertentu."""
        return self.SERVER_POOL[server_ip]

    def get_stats(self):
        """Kembalikan snapshot koneksi aktif semua server."""
        return dict(self.active_connections)