import socket
import threading

# Server configuration
HOST = '127.0.0.1'  # Localhost for testing
PORT = 65432        # Port to listen on

# Function to handle each client connection
def handle_client(conn, addr):
    """
    This function handles the client connection, sends authentication prompts,
    and exchanges messages with the client.
    """
    print(f"Connection from {addr} has been established.")
    
    # Simple user authentication (username input)
    conn.sendall("Please enter username: ".encode())
    username = conn.recv(1024).decode().strip()
    
    # Optional: You can enhance this with password checks later
    conn.sendall(f"Hello, {username}! You are now connected.\n".encode())

    # Interaction with the client
    while True:
        data = conn.recv(1024)  # Receive message from client
        if not data:  # If no data received, disconnect
            break
        print(f"Received from {addr}: {data.decode()}")
        conn.sendall("Message received.\n".encode())  # Acknowledge the message
    
    # Close the connection after message exchange
    print(f"Connection with {addr} closed.")
    conn.close()

# Function to start the server
def start_server():
    """
    This function sets up the server to accept incoming client connections,
    and starts handling them in separate threads.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))  # Bind server to HOST and PORT
        s.listen(5)  # Maximum number of queued connections
        print(f"Server started. Listening on {HOST}:{PORT}...")

        # Continuously accept new connections
        while True:
            conn, addr = s.accept()  # Accept a client connection
            client_thread = threading.Thread(target=handle_client, args=(conn, addr))
            client_thread.start()  # Handle each client in a new thread

# CLI to show server status
def server_status():
    """
    This function displays the server status when the server is started.
    """
    print("\nServer is running.")
    print(f"Listening for connections on {HOST}:{PORT}...\n")

if __name__ == "__main__":
    server_status()  # Show server status at startup
    start_server()   # Start the server to listen for connections
