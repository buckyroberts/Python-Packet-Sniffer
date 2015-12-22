import socket

s = socket.socket()

while True:
    print(s.recvfrom(65565))

# http://www.binarytides.com/python-packet-sniffer-code-linux/
