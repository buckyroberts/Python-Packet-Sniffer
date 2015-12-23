import sys
from struct import *
from parser import *

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error as err:
    print('Error creating socket' + str(err))
    sys.exit()

while True:

    # Message from a socket (buffer size) is a tuple (data received in bytes, address of socket sending the data)
    tcp_ip_packet = s.recvfrom(65565)
    packet = tcp_ip_packet[0]

    # First 20 characters is IP header - prefix to an IP packet which contains information about IP version, source IP, destination IP, time-to-live, etc...
    ip_header_packed = packet[:20]
    ip_header = unpack('!BBHHHBBH4s4s', ip_header_packed)
    ip_header_length = parse_ip_packet(ip_header)

    # Start at end of ip_header and get the next 20 characters
    tcp_header_packed = packet[ip_header_length:ip_header_length + 20]
    tcp_header = unpack('!HHLLBBHHH', tcp_header_packed)
    tcp_header_length = parse_tcp_packet(tcp_header)

    # Calculate the size of the TCP/IP header and the size of the data
    header_size = ip_header_length + tcp_header_length * 4
    data_size = len(packet) - header_size

    # Get data from the packet
    data = packet[header_size:]
    print('Data: ' + str(data))
    print('\n------------------------------\n')
