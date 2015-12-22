import socket


HOST = '127.0.0.1'
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


def send_request():
    while True:
        data = 'GET / HTTP/1.0\r\n\r\n'
        s.send(data.encode('utf-8'))
        data = s.recv(BUF_SIZE)
        if not data:
            break
        print(data.decode('utf-8'))
    s.close()


def main():
    socket_create()
    socket_connect()
    send_request()


main()

