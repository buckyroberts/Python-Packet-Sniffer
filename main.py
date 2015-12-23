import sys
from struct import *
from parser import *


# Create an INET, STREAMing socket
def socket_create():
    try:
        global s
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error as err:
        print('Error creating socket' + str(err))
        sys.exit()


# Sniff network packets
def sniff_packets():
    while True:
        # Message from a socket (buffer size) is a tuple (data received in bytes, address of socket sending the data)
        tcp_ip_packet = s.recvfrom(65565)
        packet = tcp_ip_packet[0]

        # First 20 characters is IP header - prefix to an IP packet which contains information about IP version, source IP, destination IP, time-to-live, etc...
        iph_packed = packet[:20]
        iph = unpack('!BBHHHBBH4s4s', iph_packed)
        iph_size = parse_ip_packet(iph)

        # Start at end of iph and get the next 20 characters
        tcph_packed = packet[iph_size:iph_size + 20]
        tcph = unpack('!HHLLBBHHH', tcph_packed)
        tcph_size = parse_tcp_packet(tcph)

        # Calculate the size of the TCP/IP header and the size of the data
        header_size = iph_size + tcph_size * 4
        data_size = len(packet) - header_size

        # Get data from the packet (everything after the headers)
        data = packet[header_size:]
        print('Data Size: ' + str(data_size))
        print('Data: ' + str(data))
        print('\n------------------------------\n')


def main():
    socket_create()
    sniff_packets()


main()
