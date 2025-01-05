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

def validate_query_format(data):
    """
    Validate the format of the DNS query.
    """
    if len(data) < 12:  # Minimum size for a valid DNS query
        logging.error("[INVALID QUERY FORMAT] Query too short")
        return False
    return True


def build_error_response(query, rcode):
    """
    Build a DNS error response for FORMERR, NOTIMP, REFUSED, etc.
    """
    transaction_id = query[:2]
    flags = struct.pack("!H", 0x8180 | rcode)  # Set the error code in the response
    questions = struct.pack("!H", 1)  # Number of questions
    answer_rrs = struct.pack("!H", 0)  # No answers
    authority_rrs = struct.pack("!H", 0)  # No authority records
    additional_rrs = struct.pack("!H", 0)  # No additional records
    question = query[12:]  # Include the original question section

    return transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + question

def build_dns_response_with_additional(query, rcode, answers=None, additional=None):
    transaction_id = query[:2]
    flags = struct.pack("!H", 0x8180 | rcode)  # Standard response
    questions = struct.pack("!H", 1)
    answer_rrs = struct.pack("!H", len(answers) if answers else 0)
    authority_rrs = struct.pack("!H", 0)
    additional_rrs = struct.pack("!H", len(additional) if additional else 0)
    question = query[12:]

    response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + question

    if answers:
        for answer in answers:
            response += build_resource_record(answer)

    if additional:
        for record in additional:
            response += build_resource_record(record)

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

def add_glue_records(ns_records, dns_records):
    additional = []
    for ns in ns_records:
        if ns in dns_records and "A" in dns_records[ns]:  # Check for glue record
            additional.append({"type": "A", "value": dns_records[ns]["A"], "ttl": 3600})
    return additional

class AuthoritativeServer:
    DNS_RECORDS = {
        # Example Domain Records
        "example.com": {
            "A": "93.184.216.34",
            "CNAME": "alias.example.com",
            "TXT": "Example Domain",
            "MX": "mail.example.com",
            "NS": "ns1.example.com",
        },
        "ns1.example.com": {"A": "192.0.2.1"},  # Glue record
        "mail.example.com": {"A": "93.184.216.35"},  # Mail server record
        "alias.example.com": {"A": "93.184.216.34"},  # Alias points to main server

        # Google Domain Records
        "google.com": {
            "A": "142.250.190.78",
            "TXT": "Google Services",
            "MX": "alt1.gmail-smtp-in.l.google.com",
            "NS": "ns1.google.com",
        },
        "ns1.google.com": {"A": "192.0.2.2"},  # Glue record
        "alt1.gmail-smtp-in.l.google.com": {"A": "172.217.10.27"},  # MX server

        # GitHub Domain Records
        "github.com": {
            "A": "140.82.121.4",
            "TXT": "GitHub Repository Hosting",
            "MX": "mail.github.com",
            "NS": "ns-1283.awsdns-32.org",
        },
        "mail.github.com": {"A": "192.30.252.1"},  # Mail server for GitHub

        # Facebook Domain Records
        "facebook.com": {
            "A": "157.240.23.35",
            "TXT": "Meta Social Network",
        },

        # Educational Institutions
        "nyu.edu": {
            "A": "128.122.49.42",
            "TXT": "NYU University",
        },
        "cs.umass.edu": {
            "A": "128.119.240.18",
            "TXT": "UMass CS Department",
        },

        # YouTube with CNAME Example
        "www.youtube.co": {
            "CNAME": "youtube-ui.l.google.com",
        },
        "youtube-ui.l.google.com": {
            "A": "216.58.198.78",
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
            data, addr = server_socket.recvfrom(512)
            if not validate_query_format(data):
                response = build_error_response(data, rcode=1)  # FORMERR
                server_socket.sendto(response, addr)
                continue

            domain_name = extract_domain_name(data)
            query_type = extract_query_type(data)
            logging.info(f"[QUERY RECEIVED] Domain: {domain_name}, Type: {query_type}")

            # Check if query type is supported
            supported_query_types = [1, 2, 5, 15, 16]  # A, NS, CNAME, MX, TXT
            if query_type not in supported_query_types:
                response = build_error_response(data, rcode=4)  # NOTIMP
                server_socket.sendto(response, addr)
                continue

            # Check Cache
            cached_response = self.cache.get(domain_name, query_type)
            if cached_response:
                server_socket.sendto(cached_response, addr)
                logging.info(f"[CACHE RESPONSE SENT] Domain: {domain_name}, Type: {query_type}")
                continue

            # Check DNS Records
            if domain_name in self.DNS_RECORDS:
                answers = []
                additional = []  # To store glue records
                for record_type, value in self.DNS_RECORDS[domain_name].items():
                    if query_type == 2 and record_type == "NS":  # If query is for NS
                        answers.append({"type": record_type, "value": value, "ttl": 3600})
                        additional += add_glue_records([value], self.DNS_RECORDS)
                    elif (query_type == 1 and record_type == "A") or \
                         (query_type == 5 and record_type == "CNAME") or \
                         (query_type == 16 and record_type == "TXT") or \
                         (query_type == 15 and record_type == "MX"):
                        answers.append({"type": record_type, "value": value, "ttl": 3600})
                if answers:
                    response = build_dns_response_with_additional(data, rcode=0, answers=answers, additional=additional)
                    self.cache.set(domain_name, query_type, response, ttl=3600)
                else:
                    response = build_dns_response_with_additional(data, rcode=3)  # NXDOMAIN
            else:
                response = build_dns_response_with_additional(data, rcode=3)  # NXDOMAIN

            server_socket.sendto(response, addr)
            logging.info(f"[RESPONSE SENT] Domain: {domain_name}, Type: {query_type}")

if __name__ == "__main__":
    authoritative_server = AuthoritativeServer("192.168.1.3", 8055)
    authoritative_server.start()
