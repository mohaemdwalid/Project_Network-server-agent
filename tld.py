import socket
import struct
import logging
import time
from collections import defaultdict
from threading import Thread

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - TLD SERVER - %(message)s",
    handlers=[
        logging.FileHandler("dns_server.log"),
        logging.StreamHandler()
    ]
)

class DNSCache:
    def __init__(self):
        self.cache = defaultdict(dict)

    def set(self, domain, query_type, response, ttl):
        expiry = time.time() + ttl
        self.cache[(domain, query_type)] = {"response": response, "expiry": expiry}
        logging.info(f"[CACHE SET] Domain: {domain}, Type: {query_type}, TTL: {ttl}s")

    def get(self, domain, query_type):
        if (domain, query_type) in self.cache:
            entry = self.cache[(domain, query_type)]
            if entry["expiry"] > time.time():
                logging.info(f"[CACHE HIT] Domain: {domain}, Type: {query_type}")
                return entry["response"]
            else:
                logging.info(f"[CACHE EXPIRED] Domain: {domain}, Type: {query_type}")
                del self.cache[(domain, query_type)]
        logging.info(f"[CACHE MISS] Domain: {domain}, Type: {query_type}")
        return None

def extract_domain_name(data):
    domain_name = ""
    i = 12
    while data[i] != 0:
        length = data[i]
        domain_name += data[i + 1:i + 1 + length].decode() + "."
        i += length + 1
    return domain_name[:-1]

def extract_query_type(data):
    return struct.unpack("!H", data[-4:-2])[0] if len(data) >= 14 else 1  # Default to type A

class TLDServer:
    TLD_RECORDS = {
        # Example Domain
        "example.com": {"host": "192.168.1.3", "port": 8055},
        "alias.example.com": {"host": "192.168.1.3", "port": 8055},
        "mail.example.com": {"host": "192.168.1.3", "port": 8055},
        "ns1.example.com": {"host": "192.168.1.3", "port": 8055},

        # Google Domain
        "google.com": {"host": "192.168.1.3", "port": 8055},
        "ns1.google.com": {"host": "192.168.1.3", "port": 8055},
        "alt1.gmail-smtp-in.l.google.com": {"host": "192.168.1.3", "port": 8055},

        # GitHub Domain
        "github.com": {"host": "192.168.1.3", "port": 8055},
        "mail.github.com": {"host": "192.168.1.3", "port": 8055},
        "ns-1283.awsdns-32.org": {"host": "192.168.1.3", "port": 8055},

        # Facebook Domain
        "facebook.com": {"host": "192.168.1.3", "port": 8055},

        # Educational Institutions
        "nyu.edu": {"host": "192.168.1.3", "port": 8055},
        "cs.umass.edu": {"host": "192.168.1.3", "port": 8055},

        # YouTube with CNAME Example
        "www.youtube.co": {"host": "192.168.1.3", "port": 8055},
        "youtube-ui.l.google.com": {"host": "192.168.1.3", "port": 8055},
    }


    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.cache = DNSCache()

    def handle_udp(self):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((self.host, self.port))
        logging.info(f"TLD Server UDP started on {self.host}:{self.port}")

        while True:
            data, addr = udp_socket.recvfrom(512)
            self.handle_query(data, addr, udp_socket)

    def handle_tcp(self):
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.bind((self.host, self.port))
        tcp_socket.listen(5)
        logging.info(f"TLD Server TCP started on {self.host}:{self.port}")

        while True:
            conn, addr = tcp_socket.accept()
            Thread(target=self.handle_tcp_client, args=(conn,)).start()

    def handle_tcp_client(self, conn):
        try:
            data = conn.recv(1024)
            if data:
                response = self.handle_query(data, conn.getpeername(), conn)
                conn.sendall(response)
        finally:
            conn.close()

    def handle_query(self, data, addr, socket_conn):
        domain_name = extract_domain_name(data)
        query_type = extract_query_type(data)
        logging.info(f"[QUERY RECEIVED] Domain: {domain_name}, Type: {query_type}")

        # Check Cache
        cached_response = self.cache.get(domain_name, query_type)
        if cached_response:
            socket_conn.sendto(cached_response, addr)
            logging.info(f"[CACHE RESPONSE SENT] Domain: {domain_name}, Type: {query_type}")
            return

        # Check TLD Records
        if domain_name in self.TLD_RECORDS:
            auth_info = self.TLD_RECORDS[domain_name]
            self.forward_to_authoritative(data, auth_info, query_type, addr, socket_conn)
        else:
            logging.warning(f"[NO RECORD] Domain: {domain_name} not found in TLD records")
            self.send_response(data, 3, addr, socket_conn)  # NXDOMAIN

    def forward_to_authoritative(self, query, auth_info, query_type, client_addr, server_socket):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as auth_socket:
            auth_socket.settimeout(5)
            try:
                logging.info(f"[FORWARDING TO AUTHORITATIVE] Server: {auth_info['host']}:{auth_info['port']}")
                auth_socket.sendto(query, (auth_info["host"], auth_info["port"]))
                response, _ = auth_socket.recvfrom(512)
                self.cache.set(extract_domain_name(query), query_type, response, 3600)
                server_socket.sendto(response, client_addr)
            except socket.timeout:
                logging.error(f"[AUTHORITATIVE TIMEOUT] No response from Authoritative Server")
                self.send_response(query, 2, client_addr, server_socket)  # SERVFAIL

    def send_response(self, query, rcode, client_addr, server_socket):
        response = query[:2] + struct.pack("!H", 0x8180 | rcode) + query[4:]
        server_socket.sendto(response, client_addr)

    def start(self):
        Thread(target=self.handle_udp).start()
        Thread(target=self.handle_tcp).start()

if __name__ == "__main__":
    tld_server = TLDServer("192.168.1.3", 8054)
    tld_server.start()