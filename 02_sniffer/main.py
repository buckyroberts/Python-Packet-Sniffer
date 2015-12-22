import socket
import sys
from struct import *

# create an INET, STREAMing socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error as err:
    print('Error creating socket' + str(err))
    sys.exit()


# Receive packets
while True:
    packet = s.recvfrom(65565)

    # Packet string from tuple
    packet = packet[0]

    # Take first 20 characters for the ip header
    ip_header = packet[0:20]

    # Unpack them
    iph = unpack('!BBHHHBBH4s4s', ip_header)

    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF

    iph_length = ihl * 4

    ttl = iph[5]
    protocol = iph[6]
    source_addr = socket.inet_ntoa(iph[8])
    dest_addr = socket.inet_ntoa(iph[9])

    print('Version: ' + str(version))
    print('IP Header Length: ' + str(ihl))
    print('TTL: ' + str(ttl))
    print('Protocol: ' + str(protocol))
    print('Source Address: ' + str(source_addr))
    print('Destination Address: ' + str(dest_addr))

    tcp_header = packet[iph_length:iph_length + 20]

    # Unpack them
    tcph = unpack('!HHLLBBHHH', tcp_header)

    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4

    print('Source Port: ' + str(source_port))
    print('Destination Port: ' + str(dest_port))
    print('Sequence Number: ' + str(sequence))
    print('Acknowledgement: ' + str(acknowledgement))
    print('TCP header length: ' + str(tcph_length))

    h_size = iph_length + tcph_length * 4
    data_size = len(packet) - h_size

    # get data from the packet
    data = packet[h_size:]

    print('Data: ' + str(data))
    print('\n------------------------------\n')
