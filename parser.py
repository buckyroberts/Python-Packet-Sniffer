import socket


# Parse an IP packet
def parse_ip_packet(ip_header):
    version_iphl = ip_header[0]
    version = version_iphl >> 4  # Binary right shift - the left operands value is moved right by the number of bits specified by the right operand
    iphl = version_iphl & 0xF  # Binary AND - operator copies a bit to the result if it exists in both operands

    ip_header_length = iphl * 4

    ttl = ip_header[5]
    protocol = ip_header[6]
    source_addr = socket.inet_ntoa(ip_header[8])
    dest_addr = socket.inet_ntoa(ip_header[9])

    print('IP Version: ' + str(version))
    print('IP Header Length: ' + str(iphl))
    print('TTL: ' + str(ttl))
    print('Protocol: ' + str(protocol))
    print('Source Address: ' + str(source_addr))
    print('Destination Address: ' + str(dest_addr))

    return ip_header_length


# Parse a TCP packet
def parse_tcp_packet(tcp_header):
    source_port = tcp_header[0]
    dest_port = tcp_header[1]
    sequence = tcp_header[2]
    acknowledgement = tcp_header[3]
    doff_reserved = tcp_header[4]
    tcp_header_length = doff_reserved >> 4

    print('Source Port: ' + str(source_port))
    print('Destination Port: ' + str(dest_port))
    print('Sequence Number: ' + str(sequence))
    print('Acknowledgement: ' + str(acknowledgement))
    print('TCP header length: ' + str(tcp_header_length))
    print()

    return tcp_header_length