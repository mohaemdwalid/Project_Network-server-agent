import socket

# Client configuration
HOST = '127.0.0.1'  # Server address (localhost for testing)
PORT = 65432        # Port to connect to

# Function to connect to the server
def connect_to_server():
    """
    This function connects the client to the server, authenticates the user,
    and exchanges messages with the server.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))  # Connect to the server
        
        # Receive and print server welcome message
        print(s.recv(1024).decode(), end="")  # "Please enter username: "
        username = input()  # Get the username input
        s.sendall(username.encode())  # Send username to server
        print(s.recv(1024).decode(), end="")  # "Hello, {username}!"
        
        # Start sending messages to the server
        while True:
            msg = input("Enter message to send to server: ")
            s.sendall(msg.encode())  # Send message to server
            response = s.recv(1024).decode()  # Receive server's response
            print("Server response:", response)

            if msg.lower() == 'exit':  # Exit condition
                break

if __name__ == "__main__":
    connect_to_server()  # Connect to the server and start communication
