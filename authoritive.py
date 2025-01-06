import socket
import struct
import logging
import time
from collections import defaultdict
from threading import Thread

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

def encode_domain_name(domain_name):
    parts = domain_name.split(".")
    encoded = b"".join([bytes([len(part)]) + part.encode() for part in parts])
    return encoded + b"\x00"

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
        "mail.example.com": {"A": "93.184.216.35"},  # Mail server record
        "alias.example.com": {"A": "93.184.216.34"},  # Alias points to main server

        # Google Domain Records
        "google.com": {
            "A": "142.250.190.78",
            "TXT": "Google Services",
            "MX": "alt1.gmail-smtp-in.l.google.com",
            "NS": "ns1.google.com",
        },
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
        "www.youtube.com": {
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

    def handle_udp(self):
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp_socket.bind((self.host, self.port))
        logging.info(f"Authoritative Server UDP started on {self.host}:{self.port}")

        while True:
            data, addr = udp_socket.recvfrom(512)
            self.handle_query(data, addr, udp_socket)

    def handle_tcp(self):
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.bind((self.host, self.port))
        tcp_socket.listen(5)
        logging.info(f"Authoritative Server TCP started on {self.host}:{self.port}")

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

        # Check DNS Records
        if domain_name in self.DNS_RECORDS:
            if query_type == 1:  # A Record
                answer = self.DNS_RECORDS[domain_name].get("A", None)
                if answer:
                    response = self.build_response(data, 0, [{"type": "A", "value": answer, "ttl": 3600}])
                    self.cache.set(domain_name, query_type, response, 3600)
                    socket_conn.sendto(response, addr)
                    logging.info(f"[RESPONSE SENT] A Record for {domain_name}")
                    return

            elif query_type == 5:  # CNAME Record
                cname_record = self.DNS_RECORDS[domain_name].get("CNAME", None)
                if cname_record:
                    response = self.build_response(data, 0, [{"type": "CNAME", "value": cname_record, "ttl": 3600}])
                    self.cache.set(domain_name, query_type, response, 3600)
                    socket_conn.sendto(response, addr)
                    logging.info(f"[RESPONSE SENT] CNAME Record for {domain_name}")
                    return

            elif query_type == 15:  # MX Record
                mx_record = self.DNS_RECORDS[domain_name].get("MX", None)
                if mx_record:
                    response = self.build_response(data, 0, [{"type": "MX", "value": mx_record, "ttl": 3600}])
                    self.cache.set(domain_name, query_type, response, 3600)
                    socket_conn.sendto(response, addr)
                    logging.info(f"[RESPONSE SENT] MX Record for {domain_name}")
                    return

            elif query_type == 2:  # NS Record
                ns_record = self.DNS_RECORDS[domain_name].get("NS", None)
                if ns_record:
                    response = self.build_response(data, 0, [{"type": "NS", "value": ns_record, "ttl": 3600}])
                    self.cache.set(domain_name, query_type, response, 3600)
                    socket_conn.sendto(response, addr)
                    logging.info(f"[RESPONSE SENT] NS Record for {domain_name}")
                    return

            elif query_type == 16:  # TXT Record
                txt_record = self.DNS_RECORDS[domain_name].get("TXT", None)
                if txt_record:
                    response = self.build_response(data, 0, [{"type": "TXT", "value": txt_record, "ttl": 3600}])
                    self.cache.set(domain_name, query_type, response, 3600)
                    socket_conn.sendto(response, addr)
                    logging.info(f"[RESPONSE SENT] TXT Record for {domain_name}")
                    return

        # Unsupported query type or domain not found
        logging.warning(f"[NXDOMAIN] Domain: {domain_name} not found in records")
        response = self.build_response(data, 3)  # NXDOMAIN
        socket_conn.sendto(response, addr)



    def build_response(self, query, rcode, answers=None):
        transaction_id = query[:2]
        flags = struct.pack("!H", 0x8180 | rcode)  # Standard response
        questions = struct.pack("!H", 1)
        answer_rrs = struct.pack("!H", len(answers) if answers else 0)
        authority_rrs = struct.pack("!H", 0)
        additional_rrs = struct.pack("!H", 0)
        question = query[12:]

        response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + question

        if answers:
            for answer in answers:
                response += self.build_resource_record(answer)

        return response

    def build_resource_record(self, answer):
        name = b'\xc0\x0c'  # Pointer to the domain name
        ttl = struct.pack("!I", answer["ttl"])  # Time-to-Live value
        record_class = struct.pack("!H", 1)  # IN (Internet)
        
        if answer["type"] == "A":
            record_type = struct.pack("!H", 1)  # A record
            value = socket.inet_aton(answer["value"])  # IP address
        elif answer["type"] == "CNAME":
            record_type = struct.pack("!H", 5)  # CNAME record
            value = encode_domain_name(answer["value"])  # Canonical name
        elif answer["type"] == "MX":
            record_type = struct.pack("!H", 15)  # MX record
            preference = struct.pack("!H", 10)  # Priority value (can be adjusted as needed)
            value = preference + encode_domain_name(answer["value"])  # Priority + Mail exchanger
        elif answer["type"] == "NS":
            record_type = struct.pack("!H", 2)  # NS record
            value = encode_domain_name(answer["value"])  # Name server
        elif answer["type"] == "TXT":
            record_type = struct.pack("!H", 16)  # TXT record
            value = bytes([len(answer["value"])]) + answer["value"].encode()  # TXT data
        else:
            raise ValueError(f"Unsupported record type: {answer['type']}")

        record_length = struct.pack("!H", len(value))  # Length of the record value
        return name + record_type + record_class + ttl + record_length + value


    def start(self):
        Thread(target=self.handle_udp).start()
        Thread(target=self.handle_tcp).start()

if __name__ == "__main__":
    authoritative_server = AuthoritativeServer("192.168.1.3", 8055)
    authoritative_server.start()
