import socket
import threading

# HTTP Error Codes
HTTP_STATUS_CODES = {
    200: "OK",
    400: "Bad Request",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Server Error"
}

# Function to handle client requests and implement RFC features
def handle_client(conn, addr):
    try:
        # Receive the HTTP request from the client
        request = conn.recv(1024).decode()
        print(f"Received request from {addr}:\n{request}")
        
        # Parse the request line (e.g., GET / HTTP/1.1)
        lines = request.split("\r\n")
        request_line = lines[0]
        method, path, version = request_line.split(" ")

        # Check if the request is a valid HTTP method (GET, POST, HEAD)
        if method not in ["GET", "POST", "HEAD"]:
            # Unsupported HTTP method
            send_response(conn, 405, method)
            return

        # Handle GET Request
        if method == "GET":
            if path == "/":
                send_response(conn, 200, "GET request: Welcome to the server!")
            else:
                send_response(conn, 404, f"GET request: {path} not found!")

        # Handle POST Request
        elif method == "POST":
            send_response(conn, 200, "POST request: Data received")

        # Handle HEAD Request (only headers, no body)
        elif method == "HEAD":
            send_response(conn, 200, "HEAD request: Headers sent")

    except Exception as e:
        print(f"Error while processing request from {addr}: {e}")
        send_response(conn, 500, "Internal Server Error")

    finally:
        conn.close()  # Close the connection

# Function to send HTTP response with appropriate status code and message
def send_response(conn, status_code, content):
    """
    Send an HTTP response to the client, including the status line, headers, and body content.
    """
    status_message = HTTP_STATUS_CODES.get(status_code, "Unknown Status")
    
    # Construct the HTTP response
    response = f"HTTP/1.1 {status_code} {status_message}\r\n"
    response += "Content-Type: text/plain; charset=UTF-8\r\n"
    response += "Connection: close\r\n"
    response += "\r\n"  # Blank line separating headers from body
    response += content  # Body content
    
    # Send the HTTP response to the client
    conn.sendall(response.encode())
    print(f"Sent response: {status_code} {status_message}")

# Server function to handle multiple clients using threading
def start_server():
    HOST = '127.0.0.1'
    PORT = 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(5)
        print(f"Server is running on {HOST}:{PORT}...")

        while True:
            conn, addr = s.accept()  # Accept client connection
            threading.Thread(target=handle_client, args=(conn, addr)).start()  # Handle each client in a separate thread

if __name__ == "__main__":
    start_server()  # Start the server
