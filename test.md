[ 1. APPLICATION LAYER ] - Interaksi Aplikasi & Pengguna
--------------------------------------------------------------------------

HTTP     | Hypertext Transfer Protocol          | Port 80
         | Kirim/terima data web (Teks biasa/Tidak aman)

HTTPS    | HTTP Secure                           | Port 443
         | Versi aman HTTP (Dienkripsi SSL/TLS)

DNS      | Domain Name System                    | Port 53 (UDP/TCP)
         | Buku telepon internet (Ubah Domain jadi IP Address)

DHCP     | Dynamic Host Configuration Protocol   | Port 67 (Server) / 68 (Client)
         | Menyewakan/memberikan IP otomatis ke perangkat

FTP      | File Transfer Protocol                | Port 20 (Data) / 21 (Control)
         | Upload/Download file antar komputer

SMTP     | Simple Mail Transfer Protocol         | Port 25 / 587 / 465
         | MENGIRIM email (Klien -> Server)

POP3     | Post Office Protocol v3               | Port 110 / 995 (SSL/TLS)
         | MENERIMA email (Unduh lokal & hapus dari server)

IMAP     | Internet Message Access Protocol      | Port 143 / 993 (SSL/TLS)
         | MENERIMA email (Tersinkronisasi terus di server)

SSH      | Secure Shell                           | Port 22
         | Remote access command line (Aman & Terenkripsi)

Telnet   | Teletype Network                       | Port 23
         | Remote access command line (Lama & Tidak aman)

SNMP     | Simple Network Management Protocol    | Port 161 / 162
         | Memantau, mengelola, konfigurasi perangkat jaringan

RDP      | Remote Desktop Protocol                | Port 3389
         | Remote access GUI komputer Windows (Visual)


[ 2. TRANSPORT LAYER ] - Pengiriman & Garansi Data
--------------------------------------------------------------------------

TCP      | Transmission Control Protocol        | Tidak memiliki 1 port khusus
         | Andal, berurutan, bebas error
         | (Web, Download file, dll.)

UDP      | User Datagram Protocol               | Tidak memiliki 1 port khusus
         | Sangat cepat, tanpa garansi
         | (Streaming, Game Online, dll.)


[ 3. INTERNET / NETWORK LAYER ] - Pengalamatan & Rute Paket
--------------------------------------------------------------------------

IP       | Internet Protocol (IPv4/IPv6)       | N/A
         | Memberi alamat unik & meneruskan paket di internet

ICMP     | Internet Control Message Protocol   | N/A
         | Pesan error & diagnostik jaringan (Ping, Traceroute)

ARP      | Address Resolution Protocol         | N/A
         | Translasi IP Address (Logis) -> MAC Address (Fisik)

IPsec    | Internet Protocol Security           | N/A
         | Enkripsi seluruh aliran paket IP (VPN)
         | ESP = IP Protocol 50
         | AH  = IP Protocol 51
         | IKE = UDP 500 / UDP 4500


[ 4. NETWORK ACCESS LAYER ] - Perangkat Keras & Media Fisik
--------------------------------------------------------------------------

Ethernet | Standar IEEE 802.3                   | N/A
         | Aturan pengiriman data via kabel (LAN/Kabel UTP)

Wi-Fi    | Wireless Fidelity (IEEE 802.11)      | N/A
         | Aturan pengiriman data nirkabel (Gelombang Radio)

PPP      | Point-to-Point Protocol               | N/A
         | Koneksi langsung 2 titik (Misal: Router ke ISP)


[ EXTRA: ROUTING PROTOCOLS ] - Peta Jalan Internet
--------------------------------------------------------------------------

BGP      | Border Gateway Protocol              | TCP Port 179
         | Pemandu arah internet global antar jaringan / ISP besar

OSPF     | Open Shortest Path First              | IP Protocol 89
         | Otomatis mencari route terpendek di jaringan lokal
