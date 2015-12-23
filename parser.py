import socket


# Parse an IP packet
def parse_ip_packet(iph):
    version_iphl = iph[0]
    version = version_iphl >> 4  # Binary right shift - the left operands value is moved right by the number of bits specified by the right operand
    iphl = version_iphl & 0xF  # Binary AND - operator copies a bit to the result if it exists in both operands
    iph_size = iphl * 4

    ttl = iph[5]
    protocol = iph[6]
    source_addr = socket.inet_ntoa(iph[8])
    dest_addr = socket.inet_ntoa(iph[9])

    print('IP Version: ' + str(version))
    print('IP Header Length: ' + str(iphl))
    print('TTL: ' + str(ttl))
    print('Internet Protocol: ' + str(protocol))
    print('Source Address: ' + str(source_addr))
    print('Destination Address: ' + str(dest_addr))

    return iph_size


# Parse a TCP packet
def parse_tcp_packet(tcph):
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    offset_reserved = tcph[4]
    tcph_size = offset_reserved >> 4

    print('\nSource Port: ' + str(source_port))
    print('Destination Port: ' + str(dest_port))
    print('Sequence Number: ' + str(sequence))
    print('Acknowledgement: ' + str(acknowledgement))
    print('TCP header size: ' + str(tcph_size))
    print()

    return tcph_size
