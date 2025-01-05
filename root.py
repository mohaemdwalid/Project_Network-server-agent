import socket
import struct
import logging
import time
from collections import defaultdict

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - ROOT SERVER - %(message)s",
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

class RootServer:
    ROOT_RECORDS = {
        "com": {"host": "192.168.1.3", "port": 8054},
        "net": {"host": "192.168.1.3", "port": 8054},
        "org": {"host": "192.168.1.3", "port": 8054},
        "edu": {"host": "192.168.1.3", "port": 8054},
        "io": {"host": "192.168.1.3", "port": 8054},
        "gov": {"host": "192.168.1.3", "port": 8054},
    }

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.cache = DNSCache()

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((self.host, self.port))
        logging.info(f"Root Server started on {self.host}:{self.port}")

        while True:
            data, addr = server_socket.recvfrom(512)
            domain_name = extract_domain_name(data)
            query_type = extract_query_type(data)
            logging.info(f"[QUERY RECEIVED] Domain: {domain_name}, Type: {query_type}")

            # Check Cache
            cached_response = self.cache.get(domain_name, query_type)
            if cached_response:
                server_socket.sendto(cached_response, addr)
                logging.info(f"[CACHE RESPONSE SENT] Domain: {domain_name}, Type: {query_type}")
                continue

            # Determine TLD
            tld = domain_name.split('.')[-1]

            if tld in self.ROOT_RECORDS:
                tld_info = self.ROOT_RECORDS[tld]
                self.forward_to_tld(data, tld_info, query_type, addr, server_socket)
            else:
                logging.warning(f"[INVALID TLD] No record for TLD: {tld}")
                self.send_response(data, 3, addr, server_socket)  # NXDOMAIN

    def forward_to_tld(self, query, tld_info, query_type, client_addr, server_socket):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tld_socket:
            tld_socket.settimeout(5)
            try:
                tld_socket.sendto(query, (tld_info["host"], tld_info["port"]))
                response, _ = tld_socket.recvfrom(512)
                self.cache.set(extract_domain_name(query), query_type, response, 3600)
                server_socket.sendto(response, client_addr)
            except socket.timeout:
                logging.error(f"[TLD TIMEOUT] No response from TLD Server: {tld_info['host']}:{tld_info['port']}")
                self.send_response(query, 2, client_addr, server_socket)  # SERVFAIL

    def send_response(self, query, rcode, client_addr, server_socket):
        response = query[:2] + struct.pack("!H", 0x8180 | rcode) + query[4:]
        server_socket.sendto(response, client_addr)

if __name__ == "__main__":
    root_server = RootServer("192.168.1.3", 53)
    root_server.start()
