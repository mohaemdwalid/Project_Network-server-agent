import socket
import struct
import logging
import time
from collections import defaultdict
from threading import Thread

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

    try:
        while i < len(data) and data[i] != 0:
            length = data[i]
            if i + length + 1 >= len(data):
                logging.error("[MALFORMED QUERY] Invalid domain name structure")
                return ""
            domain_name += data[i + 1:i + 1 + length].decode() + "."
            i += length + 1
    except (IndexError, UnicodeDecodeError) as e:
        logging.error(f"[MALFORMED QUERY] {e}")
        return ""
    
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
    
    def build_error_response(self, query, rcode):
        transaction_id = query[:2]
        flags = struct.pack("!H", 0x8180 | rcode)  # Set the error code in the response
        questions = query[4:6]
        answer_rrs = struct.pack("!H", 0)
        authority_rrs = struct.pack("!H", 0)
        additional_rrs = struct.pack("!H", 0)
        question = query[12:]  # Include the original question section
        return transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + question


    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.cache = DNSCache()

    def handle_udp(self):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((self.host, self.port))
        logging.info(f"Root Server UDP started on {self.host}:{self.port}")

        while True:
            data, addr = udp_socket.recvfrom(512)
            response = self.handle_query(data)
            if response:
                udp_socket.sendto(response, addr)

    def handle_tcp(self):
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.bind((self.host, self.port))
        tcp_socket.listen(5)
        logging.info(f"Root Server TCP started on {self.host}:{self.port}")

        while True:
            conn, addr = tcp_socket.accept()
            Thread(target=self.handle_tcp_client, args=(conn,)).start()

    def handle_tcp_client(self, conn):
        try:
            length_prefix = conn.recv(2)
            if len(length_prefix) < 2:
                logging.error("[TCP ERROR] Incomplete length prefix received")
                return

            query_length = struct.unpack("!H", length_prefix)[0]
            data = conn.recv(query_length)
            if len(data) < query_length:
                logging.error("[TCP ERROR] Incomplete DNS query received")
                return

            response = self.handle_query(data)
            if response:
                length_prefix = struct.pack("!H", len(response))
                conn.sendall(length_prefix + response)
        finally:
            conn.close()

    def handle_query(self, data, addr=None, socket_conn=None, is_tcp=False):
        # Extract domain name and query type
        domain_name = extract_domain_name(data)
        query_type = extract_query_type(data)
        logging.info(f"[QUERY RECEIVED] Domain: {domain_name}, Type: {query_type}")

        # Check for malformed queries
        if not domain_name:
            logging.error("[FORMERR] Malformed query")
            return self.build_error_response(data, 1)  # FORMERR

        # Check for supported query types
        supported_query_types = [1, 2, 5, 15, 16]  # A, NS, CNAME, MX, TXT
        if query_type not in supported_query_types:
            logging.error("[NOTIMP] Query type not implemented")
            return self.build_error_response(data, 4)  # NOTIMP

        # Check for server policy (REFUSED example: domain is blacklisted)
        blacklisted_domains = ["restricted.com", "blocked.com"]
        if domain_name in blacklisted_domains:
            logging.error("[REFUSED] Query refused due to policy")
            return self.build_error_response(data, 5)  # REFUSED

        # Check Cache
        cached_response = self.cache.get(domain_name, query_type)
        if cached_response:
            logging.info("[CACHE RESPONSE SENT]")
            return cached_response

        # Determine TLD
        tld = domain_name.split('.')[-1]
        if tld in self.ROOT_RECORDS:
            tld_info = self.ROOT_RECORDS[tld]
            return self.forward_to_tld(data, tld_info, query_type)
        else:
            logging.warning("[NXDOMAIN] No record for TLD")
            return self.build_error_response(data, 3)  # NXDOMAIN


    def forward_to_tld(self, query, tld_info, query_type):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tld_socket:
            tld_socket.settimeout(5)
            try:
                tld_socket.sendto(query, (tld_info["host"], tld_info["port"]))
                response, _ = tld_socket.recvfrom(512)
                self.cache.set(extract_domain_name(query), query_type, response, 3600)
                return response
            except socket.timeout:
                logging.error(f"[TLD TIMEOUT] No response from TLD Server: {tld_info['host']}:{tld_info['port']}")
                return self.build_error_response(query, 2)

    def build_error_response(self, query, rcode):
        transaction_id = query[:2]
        flags = struct.pack("!H", 0x8180 | rcode)
        questions = query[4:6]
        answer_rrs = struct.pack("!H", 0)
        authority_rrs = struct.pack("!H", 0)
        additional_rrs = struct.pack("!H", 0)
        question = query[12:]
        return transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + question

    def start(self):
        Thread(target=self.handle_udp).start()
        Thread(target=self.handle_tcp).start()

if __name__ == "__main__":
    root_server = RootServer("192.168.1.3", 53)
    root_server.start()
