import socket
import struct
import time

# Root DNS Records: TLD -> TLD Server IP and Port
ROOT_RECORDS = {
    "com": ("192.168.1.3", 8054),
    "net": ("127.0.0.3", 8054),
    "arpa": ("192.168.1.3", 8054),
}

def build_dns_response(query, answers, rcode=0):
    transaction_id = query[:2]
    flags = struct.pack("!H", 0x8180 | rcode)
    questions = struct.pack("!H", 1)
    answer_rrs = struct.pack("!H", len(answers))
    authority_rrs = struct.pack("!H", 0)
    additional_rrs = struct.pack("!H", 0)
    question = query[12:]
    response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs + question
    return response

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
    print(f"Root Server received query for {domain_name}")

    tld = domain_name.split('.')[-1]
    if tld in ROOT_RECORDS:
        tld_ip, tld_port = ROOT_RECORDS[tld]
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tld_socket:
                tld_socket.settimeout(5)
                tld_socket.sendto(data, (tld_ip, tld_port))
                response, _ = tld_socket.recvfrom(512)
                server_socket.sendto(response, addr)
        except socket.timeout:
            print(f"TLD Server {tld_ip}:{tld_port} not responding.")
            server_socket.sendto(build_dns_response(data, [], rcode=2), addr)  # SERVFAIL
    else:
        print(f"TLD {tld} not found in ROOT_RECORDS.")
        server_socket.sendto(build_dns_response(data, [], rcode=3), addr)  # NXDOMAIN

def start_dns_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    print(f"Root Server running on {host}:{port}")
    while True:
        data, addr = server_socket.recvfrom(512)
        handle_dns_query(data, addr, server_socket)

if __name__ == "__main__":
    start_dns_server("192.168.1.3", 53)
