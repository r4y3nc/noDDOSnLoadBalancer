# =========================================================
# KONFIGURASI LOAD BALANCER
# =========================================================

VIP = "10.0.0.100"
LB_MAC = "aa:bb:cc:dd:ee:ff"

SERVER_POOL = {
    "10.0.0.2": {"mac": "00:00:00:00:00:02", "port": 2},
    "10.0.0.3": {"mac": "00:00:00:00:00:03", "port": 3},
}

# =========================================================
# KONFIGURASI FIREWALL (DDoS)
# =========================================================

REQUEST_LIMIT = 10   # Maks request per TIME_WINDOW
TIME_WINDOW   = 5    # Detik
BLOCK_TIME    = 20   # Durasi blokir (detik)