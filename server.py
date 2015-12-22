import socket


HOST = ''
PORT = 9999
BUF_SIZE = 20480


# Create a socket
def socket_create():
    try:
        global server_socket
        server_socket = socket.socket()
    except socket.error as err:
        print("Could not create socket: " + str(err))


# Bind socket to port and wait for connections
def socket_bind():
    try:
        server_socket.bind((HOST, PORT))
        server_socket.listen(5)
        print("Server waiting for connection...")
    except socket.error as err:
        print("Socket binding error: " + str(err))


# Accept connection from a client
def socket_accept():
    client_socket, address = server_socket.accept()
    print("Connection has been established | " + "IP " + address[0] + " | Port " + str(address[1]))
    send_commands(client_socket)
    client_socket.close()


# Send commands
def send_commands(client_socket):
    while True:
        msg = input('Server> ')
        if msg == 'quit':
            client_socket.close()
            server_socket.close()
            break
        else:
            client_socket.send(str.encode(msg))
            client_response = str(client_socket.recv(BUF_SIZE), "utf-8")
            print(client_response)


if __name__ == '__main__':
    socket_create()
    socket_bind()
    socket_accept()
