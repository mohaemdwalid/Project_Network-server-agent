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
    if answer["type"] == "NS":
        record_type = struct.pack("!H", 2)  # NS record
        value = encode_domain_name(answer["value"])
    elif answer["type"] == "A":
        record_type = struct.pack("!H", 1)  # A record
        value = socket.inet_aton(answer["value"])
    else:
        raise ValueError("Unsupported record type")

    record_length = struct.pack("!H", len(value))
    return name + record_type + record_class + ttl + record_length + value

def encode_domain_name(domain_name):
    parts = domain_name.split(".")
    encoded = b"".join([bytes([len(part)]) + part.encode() for part in parts])
    return encoded + b"\x00"

# Root Server Logic
class RootServer:
    ROOT_RECORDS = {
        "com": {"type": "NS", "value": "192.168.1.3", "port": 8054, "ttl": 3600},
        "net": {"type": "NS", "value": "192.168.1.3", "port": 8054, "ttl": 3600},
        "org": {"type": "NS", "value": "192.168.1.3", "port": 8054, "ttl": 3600},
        "edu": {"type": "NS", "value": "192.168.1.3", "port": 8054, "ttl": 3600},
        "gov": {"type": "NS", "value": "192.168.1.3", "port": 8054, "ttl": 3600},
        "io": {"type": "NS", "value": "192.168.1.3", "port": 8054, "ttl": 3600},
        "ai": {"type": "NS", "value": "192.168.1.3", "port": 8054, "ttl": 3600},
        "info": {"type": "NS", "value": "192.168.1.3", "port": 8054, "ttl": 3600},
        "xyz": {"type": "NS", "value": "192.168.1.3", "port": 8054, "ttl": 3600},
        "biz": {"type": "NS", "value": "192.168.1.3", "port": 8054, "ttl": 3600},
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

        # Validate TLD
        tld = domain_name.split('.')[-1]
        if tld not in self.ROOT_RECORDS:
            logging.warning(f"[INVALID TLD] TLD: {tld} not supported, Transaction ID: {transaction_id}")
            response = build_dns_response(data, rcode=3)  # NXDOMAIN
            server_socket.sendto(response, addr)
            return

        # Forward to TLD server
        tld_info = self.ROOT_RECORDS[tld]
        self.forward_to_tld(data, tld_info, addr, server_socket, transaction_id)

    def forward_to_tld(self, query, tld_info, addr, server_socket, transaction_id):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tld_socket:
            tld_socket.settimeout(5)  # Timeout for TLD response
            try:
                tld_socket.sendto(query, (tld_info["value"], tld_info["port"]))
                response, _ = tld_socket.recvfrom(512)
                self.cache.set(extract_domain_name(query), response, tld_info["ttl"])
                server_socket.sendto(response, addr)
                logging.info(f"[FORWARDED TO TLD] Transaction ID: {transaction_id}, Domain: {extract_domain_name(query)}, TLD Server: {tld_info['value']}:{tld_info['port']}")
            except socket.timeout:
                logging.error(f"[TLD TIMEOUT] No response from TLD Server: {tld_info['value']}:{tld_info['port']}, Transaction ID: {transaction_id}")
                response = build_dns_response(query, rcode=2)  # SERVFAIL
                server_socket.sendto(response, addr)

if __name__ == "__main__":
    root_server = RootServer("192.168.1.3", 53)
    root_server.start()
