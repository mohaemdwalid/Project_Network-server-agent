import socket
import struct

# Function to send DNS query and receive the response
def query_dns_server(domain, server_host, server_port):
    # Build DNS query (for A record type)
    transaction_id = struct.pack("!H", 0x1234)  # Transaction ID (random for simplicity)
    flags = struct.pack("!H", 0x0100)  # Standard query
    questions = struct.pack("!H", 1)  # One question
    answer_rrs = struct.pack("!H", 0)  # No answers yet
    authority_rrs = struct.pack("!H", 0)  # No authority records
    additional_rrs = struct.pack("!H", 0)  # No additional records

    # Encode the domain name in the query (fully qualified, e.g., "example.com")
    query_name = b''.join([bytes([len(label)]) + label.encode() for label in domain.split('.')]) + b'\x00'
    query_type = struct.pack("!H", 1)  # Type A (address record)
    query_class = struct.pack("!H", 1)  # Class IN (Internet)

    query = transaction_id + flags + questions + answer_rrs + authority_rrs + additional_rrs
    query += query_name + query_type + query_class

    # Send the DNS query to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client_socket.sendto(query, (server_host, server_port))

    # Receive the response from the server
    response, _ = client_socket.recvfrom(512)  # DNS response should fit in 512 bytes
    client_socket.close()

    # Extract the IP address from the response
    ip_address = '.'.join(map(str, response[-4:]))
    return ip_address

if __name__ == "__main__":
    # Define the server details
    server_host = '192.168.1.3'  # Change to the server's IP address
    server_port = 1053           # Use the port your server is listening on

    print("Type 'exit' to quit the program.")
    
    # Input validation for number of queries
    while True:
        try:
            num_queries = int(input("Enter the number of domain names to query: "))
            if num_queries <= 0:
                print("Please enter a positive number.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid number.")

    for _ in range(num_queries):
        domain = input("Enter domain name to query (e.g., example.com): ")
        if domain.lower() == 'exit':
            print("Exiting the program.")
            break
        
        try:
            ip_address = query_dns_server(domain, server_host, server_port)
            print(f"{domain}: {ip_address}")
        except Exception as e:
            print(f"An error occurred while resolving {domain}: {e}")
