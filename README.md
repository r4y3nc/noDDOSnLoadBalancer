# SDN Firewall + Load Balancer dengan Deteksi DDoS

## Deskripsi

Proyek ini merupakan implementasi **Software Defined Networking (SDN)** menggunakan **Mininet** dan **Ryu Controller** untuk mensimulasikan sistem **Load Balancer dengan Virtual IP (VIP)** yang dilengkapi **Firewall sederhana untuk mendeteksi serangan DDoS**.

Controller akan memeriksa setiap request yang menuju **Virtual IP (VIP)**.
Jika jumlah request dari satu IP terlalu banyak dalam waktu singkat, maka IP tersebut akan **diblokir sementara selama beberapa detik**.

Sistem ini menunjukkan bagaimana **SDN dapat digunakan untuk menggabungkan fungsi keamanan jaringan dan load balancing dalam satu controller**.

---

## Arsitektur Sistem

Client mengakses layanan melalui **Virtual IP**, kemudian controller akan memproses traffic melalui firewall sebelum diarahkan ke server backend.

Alur sistem:

Client → Firewall (Deteksi DDoS) → Load Balancer → Server Backend

Topologi jaringan:

```
          Client
            h1
             |
             |
            s1
          /     \
        h2       h3
     Server1   Server2
```

---

## Komponen Sistem

* **Mininet** : Emulator jaringan untuk membuat topologi jaringan virtual
* **Ryu Controller** : Controller SDN berbasis Python
* **Open vSwitch** : Switch virtual yang mendukung OpenFlow
* **Python HTTP Server** : Backend server sederhana untuk simulasi layanan

---

## Konfigurasi Sistem

### Virtual IP

```
10.0.0.100
```

### Server Backend

```
Server 1 : 10.0.0.2
Server 2 : 10.0.0.3
```

### Algoritma Load Balancing

```
Round Robin
```

### Parameter Firewall (Deteksi DDoS)

| Parameter          | Nilai      |
| ------------------ | ---------- |
| Request Limit      | 10 request |
| Time Window        | 5 detik    |
| Blacklist Duration | 20 detik   |

Jika lebih dari **10 request dalam 5 detik** dari satu IP maka dianggap sebagai **serangan DDoS** dan IP tersebut akan **diblokir selama 20 detik**.

---

## Cara Menjalankan Sistem

### 1. Jalankan Controller

```
ryu-manager load_balancer.py
```

---

### 2. Jalankan Topologi Mininet

```
sudo mn --topo single,3 --controller remote --switch ovsk,protocols=OpenFlow13
```

---

### 3. Jalankan Backend Server

Di dalam CLI Mininet jalankan:

```
h2 python3 -m http.server 80 &
h3 python3 -m http.server 80 &
```

---

### 4. Mengakses Layanan melalui Virtual IP

Client dapat mengakses layanan menggunakan:

```
h1 curl 10.0.0.100
```

Controller akan memilih server backend secara **bergantian (Round Robin)**.

---

## Simulasi Serangan DDoS

Untuk mensimulasikan serangan DDoS dapat menggunakan perintah berikut:

```
h1 for i in {1..100}; do curl -s 10.0.0.100 & done
```

Jika serangan terdeteksi maka controller akan menampilkan log seperti:

```
!!! DDOS TERDETEKSI !!!
IP 10.0.0.1 diblokir selama 20 detik
```

Selama periode blacklist, request dari IP tersebut akan **ditolak oleh firewall**.

---

## Fitur Sistem

* Virtual IP Load Balancer
* Algoritma Round Robin
* Deteksi sederhana serangan DDoS
* Blacklist otomatis untuk attacker
* Logging trafik yang informatif
* Simulasi firewall berbasis SDN

---

## Tujuan Proyek

Proyek ini bertujuan untuk menunjukkan bagaimana **Software Defined Networking dapat digunakan untuk mengintegrasikan fungsi keamanan jaringan dan load balancing secara terpusat melalui controller**.

---

## Penulis

Proyek ini dibuat sebagai bagian dari **praktikum dan eksplorasi Software Defined Networking (SDN)** menggunakan Mininet dan Ryu Controller.
