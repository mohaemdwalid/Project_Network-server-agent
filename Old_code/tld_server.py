import socket
import struct
import time

# TLD DNS Records: Domain -> Authoritative Server IP and Port
TLD_RECORDS = {
    "example.com": ("192.168.1.3", 8055),  # Corrected IP for Authoritative Server
    "mail.com": ("127.0.0.5", 8055),
}
def build_dns_response(query, answers, rcode=0):
    """
    Build a DNS response for the TLD server.
    """
    transaction_id = query[:2]  # Copy the transaction ID from the query
    flags = struct.pack("!H", 0x8180 | rcode)  # Standard response flags
    questions = struct.pack("!H", 1)  # One question
    answer_rrs = struct.pack("!H", len(answers))  # Answer section
    authority_rrs = struct.pack("!H", 0)  # No authority records
    additional_rrs = struct.pack("!H", 0)  # No additional records
    question = query[12:]  # Copy the question section from the query

    # Build the answer section
    answer_section = b""
    for answer in answers:
        answer_section += build_answer_section(answer)

    response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs
    response += question + answer_section
    return response

def build_answer_section(answer):
    """
    Build a single answer section (e.g., A, MX, CNAME, NS).
    """
    answer_name = b'\xc0\x0c'  # Pointer to the domain name in the question
    answer_class = struct.pack("!H", 1)  # Class IN (Internet)
    answer_ttl = struct.pack("!I", 3600)  # TTL

    if answer["type"] == "A":
        answer_type = struct.pack("!H", 1)  # Type A
        answer_length = struct.pack("!H", 4)  # Length of the IP address
        answer_ip = socket.inet_aton(answer["value"])  # Convert IP to 4-byte format
        return answer_name + answer_type + answer_class + answer_ttl + answer_length + answer_ip

    elif answer["type"] == "CNAME":
        answer_type = struct.pack("!H", 5)  # Type CNAME
        cname = answer["value"]
        cname_encoded = b"".join([bytes([len(part)]) + part.encode() for part in cname.split('.')]) + b'\x00'
        cname_length = len(cname_encoded)
        return answer_name + answer_type + answer_class + answer_ttl + struct.pack("!H", cname_length) + cname_encoded

    elif answer["type"] == "MX":
        answer_type = struct.pack("!H", 15)  # Type MX
        mx_preference = struct.pack("!H", 10)  # Preference value
        mx_name = answer["value"]
        mx_encoded = b"".join([bytes([len(part)]) + part.encode() for part in mx_name.split('.')]) + b'\x00'
        mx_length = len(mx_encoded) + 2
        return answer_name + answer_type + answer_class + answer_ttl + struct.pack("!H", mx_length) + mx_preference + mx_encoded

    elif answer["type"] == "NS":
        answer_type = struct.pack("!H", 2)  # Type NS
        ns_name = answer["value"]
        ns_encoded = b"".join([bytes([len(part)]) + part.encode() for part in ns_name.split('.')]) + b'\x00'
        ns_length = len(ns_encoded)
        return answer_name + answer_type + answer_class + answer_ttl + struct.pack("!H", ns_length) + ns_encoded

    return b""


def extract_domain_name(data):
    domain_name = ""
    i = 12
    while data[i] != 0:
        length = data[i]
        domain_name += data[i + 1:i + 1 + length].decode() + "."
        i += length + 1
    return domain_name[:-1]

def handle_dns_query(data, addr, server_socket):
    domain_name = extract_domain_name(data)
    print(f"TLD Server received query for {domain_name}")

    if domain_name in TLD_RECORDS:
        auth_ip, auth_port = TLD_RECORDS[domain_name]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as auth_socket:
                auth_socket.settimeout(5)
                auth_socket.sendto(data, (auth_ip, auth_port))
                response, _ = auth_socket.recvfrom(512)
                server_socket.sendto(response, addr)
        except socket.timeout:
            print(f"Authoritative Server {auth_ip}:{auth_port} not responding.")
            server_socket.sendto(build_dns_response(data, [], rcode=2), addr)  # SERVFAIL
    else:
        print(f"Domain {domain_name} not found in TLD_RECORDS.")
        server_socket.sendto(build_dns_response(data, [], rcode=3), addr)  # NXDOMAIN

def start_dns_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    print(f"TLD Server running on {host}:{port}")
    while True:
        data, addr = server_socket.recvfrom(512)
        handle_dns_query(data, addr, server_socket)

if __name__ == "__main__":
    start_dns_server("192.168.1.3", 8054)
