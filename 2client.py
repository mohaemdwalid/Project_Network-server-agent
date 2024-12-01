import socket

def send_request(method, path):
    # Connect to the server
    HOST = '127.0.0.1'
    PORT = 65432
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        
        # Create HTTP request
        if method == "GET":
            request = f"GET {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n\r\n"
        elif method == "POST":
            data = "Hello, Server!"  # Example POST data
            request = f"POST {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\nContent-Type: text/plain\r\nContent-Length: {len(data)}\r\n\r\n{data}"
        elif method == "HEAD":
            request = f"HEAD {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n\r\n"
        else:
            print(f"Unsupported HTTP method: {method}")
            return

        # Send the request to the server
        s.sendall(request.encode())

        # Receive the response from the server
        response = s.recv(1024).decode()
        print(f"Server Response:\n{response}")
        
        # You can add more logic to process or display the response further

if __name__ == "__main__":
    # Example: Send GET, POST, and HEAD requests
    print("Sending GET request to the server...")
    send_request("GET", "/")

    print("\nSending POST request to the server...")
    send_request("POST", "/data")

    print("\nSending HEAD request to the server...")
    send_request("HEAD", "/")
