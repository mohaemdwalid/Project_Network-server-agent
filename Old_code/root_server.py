import socket
import struct
import time

# Root DNS Records: TLD -> TLD Server IP and Port
ROOT_RECORDS = {
    "com": ("192.168.1.3", 8054),
    "net": ("192.168.1.3", 8054),
    "arpa": ("192.168.1.3", 8054),
}

TTL = 3600  # Default Time-to-Live for records

def build_dns_response(query, answers, authority, additional, rcode=0):
    """Build a DNS response packet."""
    transaction_id = query[:2]
    flags = struct.pack("!H", 0x8180 | rcode)  # Standard response
    questions = struct.pack("!H", 1)  # One question
    answer_rrs = struct.pack("!H", len(answers))
    authority_rrs = struct.pack("!H", len(authority))
    additional_rrs = struct.pack("!H", len(additional))
    question = query[12:]  # Copy the question section

    # Combine all sections
    response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs
    response += question
    response += b"".join(answers)
    response += b"".join(authority)
    response += b"".join(additional)

    return response

def build_ns_record(domain_name, ns_name):
    """Build an NS record for the AUTHORITY SECTION."""
    answer_name = b'\xc0\x0c'  # Pointer to the queried domain
    answer_type = struct.pack("!H", 2)  # NS record
    answer_class = struct.pack("!H", 1)  # Class IN
    answer_ttl = struct.pack("!I", TTL)
    ns_encoded = b"".join([bytes([len(part)]) + part.encode() for part in ns_name.split('.')]) + b'\x00'
    ns_length = len(ns_encoded)
    return answer_name + answer_type + answer_class + answer_ttl + struct.pack("!H", ns_length) + ns_encoded

def build_a_record(domain_name, ip_address):
    """Build an A record for the ADDITIONAL SECTION."""
    answer_name = b'\xc0\x2c'  # Pointer to the NS domain
    answer_type = struct.pack("!H", 1)  # A record
    answer_class = struct.pack("!H", 1)  # Class IN
    answer_ttl = struct.pack("!I", TTL)
    answer_length = struct.pack("!H", 4)  # IP address length
    answer_ip = socket.inet_aton(ip_address)
    return answer_name + answer_type + answer_class + answer_ttl + answer_length + answer_ip

def extract_domain_name(data):
    """Extract the domain name from the DNS query."""
    domain_name = ""
    i = 12  # Skip the header
    while data[i] != 0:
        length = data[i]
        domain_name += data[i + 1:i + 1 + length].decode() + "."
        i += length + 1
    return domain_name[:-1]  # Remove the trailing dot

def is_recursive_query(data):
    """Check if the query is recursive by inspecting the RD flag."""
    flags = struct.unpack("!H", data[2:4])[0]
    rd_flag = flags & 0x0100  # Recursion Desired bit
    return bool(rd_flag)

def handle_dns_query(data, addr, server_socket):
    """Handle incoming DNS queries and process based on the type."""
    domain_name = extract_domain_name(data)
    if not domain_name:
        print("Invalid query received. Sending SERVFAIL.")
        response = build_dns_response(data, [], [], [], rcode=2)  # SERVFAIL
        server_socket.sendto(response, addr)
        return

    query_type = "Recursive" if is_recursive_query(data) else "Iterative"
    print(f"Root Server received {query_type} query for {domain_name}")

    tld = domain_name.split('.')[-1]
    if tld in ROOT_RECORDS:
        tld_ip, tld_port = ROOT_RECORDS[tld]

        # Construct AUTHORITY and ADDITIONAL sections
        authority = [build_ns_record(domain_name, f"{tld}.root-servers.net")]
        additional = [build_a_record(f"{tld}.root-servers.net", tld_ip)]

        if query_type == "Iterative":
            print("Returning TLD server info for iterative query.")
            response = build_dns_response(data, [], authority, additional, rcode=0)
            server_socket.sendto(response, addr)
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tld_socket:
                    tld_socket.settimeout(5)
                    tld_socket.sendto(data, (tld_ip, tld_port))
                    response, _ = tld_socket.recvfrom(512)
                    print("Forwarding recursive response to the client.")
                    server_socket.sendto(response, addr)
            except socket.timeout:
                print(f"TLD Server {tld_ip}:{tld_port} not responding.")
                response = build_dns_response(data, [], [], [], rcode=2)  # SERVFAIL
                server_socket.sendto(response, addr)
    else:
        print(f"TLD {tld} not found in ROOT_RECORDS.")
        response = build_dns_response(data, [], [], [], rcode=3)  # NXDOMAIN
        server_socket.sendto(response, addr)

def start_dns_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    print(f"Root Server running on {host}:{port}")
    while True:
        data, addr = server_socket.recvfrom(512)
        handle_dns_query(data, addr, server_socket)

if __name__ == "__main__":
    start_dns_server("192.168.1.3", 53)
