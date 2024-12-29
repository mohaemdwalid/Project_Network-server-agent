import socket
import struct
import logging
import time
from collections import defaultdict

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - AUTHORITATIVE SERVER - %(message)s",
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

    def clear_expired(self):
        expired_domains = [domain for domain, entry in self.cache.items() if entry["expiry"] <= time.time()]
        for domain in expired_domains:
            del self.cache[domain]
            logging.info(f"[CACHE CLEANED] Expired entry for domain: {domain}")

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
    elif answer["type"] == "TXT":
        record_type = struct.pack("!H", 16)  # TXT record
        value = bytes([len(answer["value"])]) + answer["value"].encode()
    elif answer["type"] == "MX":
        record_type = struct.pack("!H", 15)  # MX record
        preference = struct.pack("!H", 10)  # Preference value
        value = preference + encode_domain_name(answer["value"])
    elif answer["type"] == "NS":
        record_type = struct.pack("!H", 2)  # NS record
        value = encode_domain_name(answer["value"])
    else:
        raise ValueError("Unsupported record type")

    record_length = struct.pack("!H", len(value))
    return name + record_type + record_class + ttl + record_length + value


def encode_domain_name(domain_name):
    parts = domain_name.split(".")
    encoded = b"".join([bytes([len(part)]) + part.encode() for part in parts])
    return encoded + b"\x00"

# Authoritative Server Logic
class AuthoritativeServer:
    DNS_RECORDS = {
        "example.com": {
            "A": "93.184.216.34",
            "CNAME": "alias.example.com",
            "NS": "ns1.example.com",
            "MX": "mail.example.com",
            "TXT": "Example Domain",
        },
        "mail.example.com": {"A": "93.184.216.35"},
        "alias.example.com": {"A": "93.184.216.34"},
        "google.com": {
            "A": "142.250.190.78",
            "TXT": "Google Services",
            "MX": "alt1.gmail-smtp-in.l.google.com",  # Realistic MX record
            "NS": "ns1.google.com",  # Realistic NS record
        },
        "github.com": {
            "A": "140.82.121.4",
            "TXT": "GitHub Repository Hosting",
            "MX": "mail.github.com",  # Realistic MX record
            "NS": "ns-1283.awsdns-32.org",  # Realistic NS record
        },
        "facebook.com": {
            "A": "157.240.23.35",
            "TXT": "Meta Social Network",
        },
        "nyu.edu": {
            "A": "128.122.49.42",
            "TXT": "NYU University",
        },
        "cs.umass.edu": {
            "A": "128.119.240.18",
            "TXT": "UMass CS Department",
        },
        "www.youtube.co": {
            "CNAME": "youtube-ui.l.google.com",  # CNAME pointing to the actual service
        },
        "youtube-ui.l.google.com": {
            "A": "216.58.198.78",  # IP address of youtube-ui.l.google.com
        },
    }

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.cache = DNSCache()

    def start(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((self.host, self.port))
        logging.info(f"Authoritative Server started on {self.host}:{self.port}")
        while True:
            self.cache.clear_expired()
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

        # Resolve domain
        if domain_name in self.DNS_RECORDS:
            answers = []
            for record_type, value in self.DNS_RECORDS[domain_name].items():
                answers.append({"type": record_type, "value": value, "ttl": 3600})
            response = build_dns_response(data, rcode=0, answers=answers)
            self.cache.set(domain_name, response, ttl=3600)
        else:
            logging.warning(f"[NO RECORD] Domain: {domain_name} not found, Transaction ID: {transaction_id}")
            response = build_dns_response(data, rcode=3)  # NXDOMAIN

        server_socket.sendto(response, addr)
        logging.info(f"[RESPONSE SENT] Transaction ID: {transaction_id}, Domain: {domain_name}")

if __name__ == "__main__":
    authoritative_server = AuthoritativeServer("192.168.1.3", 8055)
    authoritative_server.start()
