import socket
import struct

# DNS Records for Authoritative Server
DNS_RECORDS = {
    "example.com": {"A": "93.184.216.34"},
    "mail.com": {"A": "93.184.216.35"},
}

def extract_domain_name(data):
    domain_name = ""
    i = 12
    while data[i] != 0:
        length = data[i]
        domain_name += data[i + 1:i + 1 + length].decode() + "."
        i += length + 1
    return domain_name[:-1]

def build_dns_response(query, answers, rcode=0):
    transaction_id = query[:2]
    flags = struct.pack("!H", 0x8180 | rcode)
    questions = struct.pack("!H", 1)
    answer_rrs = struct.pack("!H", len(answers))
    authority_rrs = struct.pack("!H", 0)
    additional_rrs = struct.pack("!H", 0)
    question = query[12:]
    response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + question
    for answer in answers:
        response += build_A_record(answer)
    return response

def build_A_record(answer):
    answer_name = b'\xc0\x0c'
    answer_type = struct.pack("!H", 1)
    answer_class = struct.pack("!H", 1)
    answer_ttl = struct.pack("!I", 3600)
    answer_length = struct.pack("!H", 4)
    answer_ip = socket.inet_aton(answer)
    return answer_name + answer_type + answer_class + answer_ttl + answer_length + answer_ip

def handle_dns_query(data, addr, server_socket):
    domain_name = extract_domain_name(data)
    print(f"Authoritative Server received query for {domain_name}")

    if domain_name in DNS_RECORDS:
        ip = DNS_RECORDS[domain_name]["A"]
        response = build_dns_response(data, [ip])
    else:
        response = build_dns_response(data, [], rcode=3)  # NXDOMAIN

    server_socket.sendto(response, addr)

def start_dns_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    print(f"Authoritative Server running on {host}:{port}")
    while True:
        data, addr = server_socket.recvfrom(512)
        handle_dns_query(data, addr, server_socket)

if __name__ == "__main__":
    start_dns_server("192.168.1.3", 8055)
