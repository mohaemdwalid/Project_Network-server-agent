import socket
import struct
import random

# A simple database of domain -> IP mappings
DNS_RECORDS = {
    "example.com": "93.184.216.34",  # example.com resolves to this IP
    "localhost": "127.0.0.1",
    "netflix.com": ["54.74.73.31", "54.155.178.5", "3.251.50.149"] 
}

# Function to build DNS response
def build_dns_response(query, ip_addresses):
    transaction_id = query[:2]
    flags = struct.pack("!H", 0x8180)  # Standard query response, no error
    questions = struct.pack("!H", 1)  # One question
    answer_rrs = struct.pack("!H", len(ip_addresses))  # Number of answer records
    authority_rrs = struct.pack("!H", 0)
    additional_rrs = struct.pack("!H", 0)
    question = query[12:]

    # Build the answer section for multiple IPs
    answers = b""
    for ip in ip_addresses:
        answer_name = b'\xc0\x0c'  # Pointer to the domain name in the question
        answer_type = struct.pack("!H", 1)  # Type A (IPv4 address)
        answer_class = struct.pack("!H", 1)  # Class IN (Internet)
        answer_ttl = struct.pack("!I", 3600)  # TTL (time to live)
        answer_length = struct.pack("!H", 4)  # Length of the IP address
        answer_ip = socket.inet_aton(ip)  # Convert IP to 4-byte format
        answers += answer_name + answer_type + answer_class + answer_ttl + answer_length + answer_ip

    response = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs
    response += question + answers
    return response

# Function to handle incoming DNS queries
def handle_dns_query(data, addr, server_socket):
    try:
        # Extract the domain name from the query
        domain_name = ""
        i = 12  # Skip the header

        while data[i] != 0:
            length = data[i]
            domain_name += data[i+1:i+1+length].decode() + "."
            i += length + 1

        domain_name = domain_name[:-1]  # Remove the trailing dot
        
        print(f"Received query for domain: {domain_name}")

        # Check if the domain exists in the DNS records
        if domain_name in DNS_RECORDS:
            ip_addresses = DNS_RECORDS[domain_name]
            if isinstance(ip_addresses, list):
                ip_to_return = random.choice(ip_addresses)  # Randomly pick one IP for this query
            else:
                ip_to_return = ip_addresses
            print(f"Resolved {domain_name} to {ip_to_return}")
            response = build_dns_response(data, [ip_to_return])
        else:
            print(f"Domain {domain_name} not found")
            response = build_dns_response(data, ["0.0.0.0"])  # Respond with an empty IP (indicating error)

        # Send the response back to the client
        server_socket.sendto(response, addr)
    
    except Exception as e:
        print(f"Error handling DNS query: {e}")

# DNS Server
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
    host = '192.168.1.3'  # Change to your server's IP
    port = 1053           # Port to listen on
    start_dns_server(host, port)
