import socket


HOST = ''
PORT = 9999
BUF_SIZE = 20480


# Create a socket
def socket_create():
    try:
        global s
        s = socket.socket()
    except socket.error as err:
        print("Could not create socket: " + str(err))


# Bind socket to port and wait for connections
def socket_bind():
    try:
        s.bind((HOST, PORT))
        s.listen(5)
    except socket.error as err:
        print("Socket binding error: " + str(err))


# Accept connection from a client
def socket_accept():
    conn, address = s.accept()
    print("Connection has been established | " + "IP " + address[0] + " | Port " + str(address[1]))
    conn.close()


if __name__ == '__main__':
    socket_create()
    socket_bind()
    socket_accept()
