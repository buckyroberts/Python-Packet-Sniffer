import socket


HOST = '192.168.0.5'
PORT = 9999
BUF_SIZE = 20480


# Create a socket
def socket_create():
    try:
        global s
        s = socket.socket()
    except socket.error as err:
        print("Could not create socket: " + str(err))


# Connect to a remote socket
def socket_connect():
    try:
        s.connect((HOST, PORT))
    except socket.error as err:
        print("Socket connection error: " + str(err))


# Receive messages from remote server and run on local machine
def receive_messages():
    while True:
        data = s.recv(BUF_SIZE)
        print('Server> ' + data[:].decode("utf-8"))
        s.send(str.encode('Client> ok'))
    s.close()


def main():
    socket_create()
    socket_connect()
    receive_messages()


main()

