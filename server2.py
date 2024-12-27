import socket
import struct
import random
import threading
import time
# root - tld - authoritative - tld 
# A simple database of domain -> IP mappings
DNS_RECORDS = {
    "example.com": ["93.184.216.34"],  # example.com resolves to this IP
    "localhost": ["127.0.0.1"],
    "netflix.com": ["54.74.73.31", "54.155.178.5", "3.251.50.149"],
    "alias.com": {"CNAME": "example.com"},  # Alias for example.com
    "mail.com": {"MX": ["mail.mail.com"]},  # Mail Exchange record
    "networking.net": ["93.184.216.37", "93.184.216.38"],  # Example multiple A records
    "ns.example.com": {"NS": ["ns1.example.com"]},  # Name Server Record
    "soa.example.com": {"SOA": "ns.example.com. hostmaster.example.com. 20220101 3600 1800 1209600 86400"},  # SOA Record
    "reverse.1.168.192.in-addr.arpa": ["93.184.216.34"],  # PTR Record (reverse lookup)
}

# Cache to store resolved queries with TTL
CACHE = {}
TTL = 60  # Default TTL for cache entries (in seconds)

def build_dns_response(query, answers, authority=[], additional=[], rcode=0):
    transaction_id = query[:2]
    flags = struct.pack("!H", 0x8180 | rcode)  # Standard query response
    questions = struct.pack("!H", 1)  # One question
    answer_rrs = struct.pack("!H", len(answers))  # Number of answer records
    authority_rrs = struct.pack("!H", len(authority))  # Number of authority records
    additional_rrs = struct.pack("!H", len(additional))  # Number of additional records
    question = query[12:]

    # Build the answer section
    answer_section = b""
    for answer in answers:
        if answer["type"] == "A":
            answer_name = b'\xc0\x0c'  # Pointer to the domain name in the question
            answer_type = struct.pack("!H", 1)  # Type A (IPv4 address)
            answer_class = struct.pack("!H", 1)  # Class IN (Internet)
            answer_ttl = struct.pack("!I", 3600)  # TTL (time to live)
            answer_length = struct.pack("!H", 4)  # Length of the IP address
            answer_ip = socket.inet_aton(answer["value"])  # Convert IP to 4-byte format
            answer_section += answer_name + answer_type + answer_class + answer_ttl + answer_length + answer_ip
        elif answer["type"] == "CNAME":
            answer_name = b'\xc0\x0c'  # Pointer to the domain name in the question
            answer_type = struct.pack("!H", 5)  # Type CNAME
            answer_class = struct.pack("!H", 1)  # Class IN (Internet)
            answer_ttl = struct.pack("!I", 3600)  # TTL (time to live)
            cname = answer["value"]
            cname_encoded = b"".join([bytes([len(part)]) + part.encode() for part in cname.split('.')]) + b'\x00'
            cname_length = len(cname_encoded)
            answer_section += (
                answer_name
                + answer_type
                + answer_class
                + answer_ttl
                + struct.pack("!H", cname_length)
                + cname_encoded
            )
        elif answer["type"] == "MX":
            answer_name = b'\xc0\x0c'  # Pointer to the domain name in the question
            answer_type = struct.pack("!H", 15)  # Type MX
            answer_class = struct.pack("!H", 1)  # Class IN (Internet)
            answer_ttl = struct.pack("!I", 3600)  # TTL (time to live)
            mx_exchange = answer["value"]
            mx_encoded = b"".join([bytes([len(part)]) + part.encode() for part in mx_exchange.split('.')]) + b'\x00'
            mx_length = len(mx_encoded)
            answer_section += (
                answer_name
                + answer_type
                + answer_class
                + answer_ttl
                + struct.pack("!H", mx_length)
                + mx_encoded
            )
        elif answer["type"] == "NS":
            answer_name = b'\xc0\x0c'  # Pointer to the domain name in the question
            answer_type = struct.pack("!H", 2)  # Type NS
            answer_class = struct.pack("!H", 1)  # Class IN (Internet)
            answer_ttl = struct.pack("!I", 3600)  # TTL (time to live)
            ns_name = answer["value"]
            ns_encoded = b"".join([bytes([len(part)]) + part.encode() for part in ns_name.split('.')]) + b'\x00'
            ns_length = len(ns_encoded)
            answer_section += (
                answer_name
                + answer_type
                + answer_class
                + answer_ttl
                + struct.pack("!H", ns_length)
                + ns_encoded
            )

    response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs
    response += question + answer_section
    return response

def resolve_record(domain_name):
    """
    Resolves a domain name to its final records (A, CNAME, MX, NS, or PTR).
    Handles recursive resolution of CNAME records and PTR for reverse lookups.
    """
    domain_name = domain_name.lower()  # Ensure case-insensitive matching

    # Check cache first
    now = time.time()
    if domain_name in CACHE:
        entry = CACHE[domain_name]
        if now - entry['timestamp'] < TTL:  # Check if cache entry is valid
            print(f"Cache hit for {domain_name}")
            return entry['data'], 0
        else:
            del CACHE[domain_name]  # Expire cache entry

    if domain_name not in DNS_RECORDS:
        return [], 3  # NXDOMAIN

    record = DNS_RECORDS[domain_name]
    answers = []

    if isinstance(record, dict):
        if "CNAME" in record:
            cname_target = record["CNAME"]
            print(f"Resolving CNAME {domain_name} -> {cname_target}")
            answers, rcode = resolve_record(cname_target)
            if rcode == 0:
                answers.insert(0, {"type": "CNAME", "value": cname_target})
            return answers, rcode
        elif "MX" in record:
            answers = [{"type": "MX", "value": mx} for mx in record["MX"]]
            return answers, 0
        elif "NS" in record:
            answers = [{"type": "NS", "value": ns} for ns in record["NS"]]
            return answers, 0
        elif "SOA" in record:
            answers = [{"type": "SOA", "value": record["SOA"]}]
            return answers, 0
    else:
        ip_addresses = record if isinstance(record, list) else [record]
        answers = [{"type": "A", "value": ip} for ip in ip_addresses]
        
    # Cache the resolved records
    CACHE[domain_name] = {'data': answers, 'timestamp': now}
    return answers, 0

def handle_dns_query(data, addr, server_socket):
    try:
        # Extract the domain name from the query
        domain_name = ""
        i = 12  # Skip the header

        while data[i] != 0:
            length = data[i]
            if length > 63 or i + length + 1 > len(data):
                raise ValueError("Invalid query format")
            domain_name += data[i + 1:i + 1 + length].decode() + "."
            i += length + 1

        domain_name = domain_name[:-1]  # Remove the trailing dot

        print(f"Received query for domain: {domain_name}")

        # Check for refused domains
        if domain_name in ["blocked.com"]:
            print(f"Query for {domain_name} is refused.")
            response = build_dns_response(data, [], rcode=5)  # REFUSED
            server_socket.sendto(response, addr)
            return

        # Resolve the domain name
        answers, rcode = resolve_record(domain_name)
        if rcode == 0:
            print(f"Resolved {domain_name} to {answers}")
        else:
            print(f"Failed to resolve {domain_name}, rcode: {rcode}")

        # Build and send the response
        response = build_dns_response(data, answers, rcode=rcode)
        server_socket.sendto(response, addr)
    
    except ValueError as e:
        print(f"Malformed query: {e}")
        response = build_dns_response(data, [], rcode=1)  # FORMERR
        server_socket.sendto(response, addr)
    except Exception as e:
        print(f"Error handling DNS query: {e}")
        response = build_dns_response(data, [], rcode=2)  # SERVFAIL
        server_socket.sendto(response, addr)

def start_dns_server(host, port):
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((host, port))
        print(f"DNS Server started on {host}:{port}")

        while True:
            # Receive DNS query from a client
            data, addr = server_socket.recvfrom(512)  # DNS queries are typically < 512 bytes
            print(f"Received data from {addr}")
            handle_dns_query(data, addr, server_socket)
    except Exception as e:
        print(f"Error starting DNS server: {e}")

if __name__ == "__main__":
    host = '192.168.1.3'  # Bind to the server's IP address
    port = 53           # Port to listen on
    start_dns_server(host, port)
