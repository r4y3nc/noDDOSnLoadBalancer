from __future__ import print_function

import time


class DDoSDetector(object):
    """
    Deteksi serangan DDoS berbasis rate limiting per IP.
    """

    def __init__(self, request_limit=10, time_window=5, block_time=20, logger=None):
        self.REQUEST_LIMIT = request_limit
        self.TIME_WINDOW   = time_window
        self.BLOCK_TIME    = block_time
        self.logger        = logger

        self.request_table = {}
        self.blacklist     = {}

    def cek_ddos(self, ip):
        """
        Periksa apakah IP melebihi batas request.
        Return True jika IP harus diblokir.
        """
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

            if self.logger:
                self.logger.warning("!!! DDOS TERDETEKSI !!!")
                self.logger.warning(
                    "IP %s diblokir selama %s detik", ip, self.BLOCK_TIME
                )

            return True

        return False