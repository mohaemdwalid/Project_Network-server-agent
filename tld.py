import socket
import struct
import logging
import time
from collections import defaultdict

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - TLD SERVER - %(message)s",
    handlers=[
        logging.FileHandler("dns_server.log"),
        logging.StreamHandler()
    ]
)

# Cache with TTL Support
class DNSCache:
    def __init__(self):
        self.cache = defaultdict(dict)

    def set(self, domain, response, ttl):
        expiry = time.time() + ttl
        self.cache[domain] = {"response": response, "expiry": expiry}
        logging.info(f"[CACHE SET] Domain: {domain}, TTL: {ttl}s")

    def get(self, domain):
        if domain in self.cache:
            entry = self.cache[domain]
            if entry["expiry"] > time.time():
                logging.info(f"[CACHE HIT] Domain: {domain}")
                return entry["response"]
            else:
                logging.info(f"[CACHE EXPIRED] Domain: {domain}")
                del self.cache[domain]
        logging.info(f"[CACHE MISS] Domain: {domain}")
        return None

# Utility functions
def extract_domain_name(data):
    domain_name = ""
    i = 12
    while data[i] != 0:
        length = data[i]
        domain_name += data[i + 1:i + 1 + length].decode() + "."
        i += length + 1
    return domain_name[:-1]

def build_dns_response(query, rcode, answers=None):
    transaction_id = query[:2]
    flags = struct.pack("!H", 0x8180 | rcode)  # Standard response, recursion available
    questions = struct.pack("!H", 1)
    answer_rrs = struct.pack("!H", len(answers) if answers else 0)
    authority_rrs = struct.pack("!H", 0)
    additional_rrs = struct.pack("!H", 0)
    question = query[12:]

    response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + question

    if answers:
        for answer in answers:
            response += build_resource_record(answer)

    return response

def build_resource_record(answer):
    name = b'\xc0\x0c'
    ttl = struct.pack("!I", answer["ttl"])
    record_class = struct.pack("!H", 1)
    if answer["type"] == "A":
        record_type = struct.pack("!H", 1)  # A record
        value = socket.inet_aton(answer["value"])
    elif answer["type"] == "CNAME":
        record_type = struct.pack("!H", 5)  # CNAME record
        value = encode_domain_name(answer["value"])
    else:
        raise ValueError("Unsupported record type")

    record_length = struct.pack("!H", len(value))
    return name + record_type + record_class + ttl + record_length + value

def encode_domain_name(domain_name):
    parts = domain_name.split(".")
    encoded = b"".join([bytes([len(part)]) + part.encode() for part in parts])
    return encoded + b"\x00"

# TLD Server Logic
class TLDServer:
    TLD_RECORDS = {
        "example.com": {"type": "A", "value": "93.184.216.34", "ttl": 3600},
        "mail.example.com": {"type": "A", "value": "93.184.216.35", "ttl": 3600},
        "google.com": {"type": "A", "value": "142.250.190.78", "ttl": 3600},
        "github.com": {"type": "A", "value": "140.82.121.4", "ttl": 3600},
        "facebook.com": {"type": "A", "value": "157.240.23.35", "ttl": 3600},
        "nyu.edu": {"type": "A", "value": "128.122.49.42", "ttl": 3600},
        "cs.umass.edu": {"type": "A", "value": "128.119.240.18", "ttl": 3600},
    }

    AUTHORITATIVE_SERVERS = {
        "example.com": {"host": "192.168.1.3", "port": 8055},
        "mail.example.com": {"host": "192.168.1.3", "port": 8055},
        "google.com": {"host": "192.168.1.3", "port": 8055},
        "github.com": {"host": "192.168.1.3", "port": 8055},
        "facebook.com": {"host": "192.168.1.3", "port": 8055},
        "nyu.edu": {"host": "192.168.1.3", "port": 8055},
        "cs.umass.edu": {"host": "192.168.1.3", "port": 8055},
    }

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.cache = DNSCache()

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((self.host, self.port))
        logging.info(f"TLD Server started on {self.host}:{self.port}")
        while True:
            data, addr = server_socket.recvfrom(512)
            self.handle_query(data, addr, server_socket)

    def handle_query(self, data, addr, server_socket):
        domain_name = extract_domain_name(data)
        transaction_id = int.from_bytes(data[:2], "big")
        logging.info(f"[QUERY RECEIVED] Transaction ID: {transaction_id}, Domain: {domain_name}")

        # Check cache
        cached_response = self.cache.get(domain_name)
        if cached_response:
            server_socket.sendto(cached_response, addr)
            logging.info(f"[CACHE RESPONSE SENT] Transaction ID: {transaction_id}, Domain: {domain_name}")
            return

        # Validate domain
        if domain_name not in self.TLD_RECORDS:
            logging.warning(f"[NO RECORD] Domain: {domain_name} not found in TLD_RECORDS, Transaction ID: {transaction_id}")
            response = build_dns_response(data, rcode=3)  # NXDOMAIN
            server_socket.sendto(response, addr)
            return

        # Forward to Authoritative Server if applicable
        if domain_name in self.AUTHORITATIVE_SERVERS:
            auth_info = self.AUTHORITATIVE_SERVERS[domain_name]
            self.forward_to_authoritative(data, domain_name, auth_info, addr, server_socket, transaction_id)
        else:
            record = self.TLD_RECORDS[domain_name]
            response = build_dns_response(data, rcode=0, answers=[record])
            self.cache.set(domain_name, response, record["ttl"])
            server_socket.sendto(response, addr)
            logging.info(f"[RESPONSE SENT] Transaction ID: {transaction_id}, Domain: {domain_name}, Record: {record}")

    def forward_to_authoritative(self, query, domain_name, auth_info, addr, server_socket, transaction_id):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as auth_socket:
            auth_socket.settimeout(5)  # Timeout for authoritative response
            try:
                auth_socket.sendto(query, (auth_info["host"], auth_info["port"]))
                response, _ = auth_socket.recvfrom(512)
                self.cache.set(domain_name, response, 3600)
                server_socket.sendto(response, addr)
                logging.info(f"[FORWARDED TO AUTHORITATIVE] Transaction ID: {transaction_id}, Domain: {domain_name}, Server: {auth_info['host']}:{auth_info['port']}")
            except socket.timeout:
                logging.error(f"[AUTHORITATIVE TIMEOUT] Transaction ID: {transaction_id}, Domain: {domain_name}, Server: {auth_info['host']}:{auth_info['port']}")
                response = build_dns_response(query, rcode=2)  # SERVFAIL
                server_socket.sendto(response, addr)

if __name__ == "__main__":
    tld_server = TLDServer("192.168.1.3", 8054)
    tld_server.start()
