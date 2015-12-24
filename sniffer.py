import socket
import struct
import textwrap


def format_multiline(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line
                      for line in textwrap.wrap(string, size)])


# Returns MAC as string from bytes
def get_mac_address(bytes_address):
    byte_str = map('{:02x}'.format, bytes_address)
    mac_address = ':'.join(byte_str).upper()
    return mac_address


# Unpack ethernet frame
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_address(dest_mac), get_mac_address(src_mac), socket.htons(proto), data[14:]


def ipv4(address):
    return '.'.join(map(str, address))


def ipv4_packet(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15) * 4

    ttl, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

    return (version, header_length, ttl, protocol, ipv4(source), ipv4(target),
            data[header_length:])


def icmp_packet(data):
    type, code, checksum = struct.unpack('! B B H', data[:4])
    return type, code, checksum, data[4:]


def tcp_segment(data):
    (source_port, destination_port, sequence, acknowledgment,
     offset_reserved_flags) = struct.unpack('! H H L L H', data[:14])

    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    return (source_port, destination_port, sequence, acknowledgment, flag_urg,
            flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:])


def udp_segment(data):
    src_port, dest_port, size = struct.unpack('! H H 2x H', data[:8])
    return src_port, dest_port, size, data[8:]


if __name__ == '__main__':

    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        data, address = connection.recvfrom(65535)
        destination, source, protocol, data = ethernet_frame(data)

        print('Ethernet Frame:')
        print('| - Destination: {}, Source: {}, Protocol: {}'.format(destination, source, protocol))

        if protocol == 8:
            (version, header_length, ttl, protocol, source, target,
             data) = ipv4_packet(data)

            print('| - IPv4 Packet:')
            print('    | - Version: {}, Header Length: {}, TTL: {},'.format(version, header_length, ttl))
            print('    | - Protocol: {}, Source: {}, Target: {}'.format(protocol, source, target))

            # ICMP
            if protocol == 1:
                type, code, checksum, data = icmp_packet(data)
                print('    | - ICMP Packet:')
                print('        | - Type: {}, Code: {}, Checksum: {},'.format(type, code, checksum))
                print('        | - Data:')
                print(format_multiline('            | - ', data))

            # TCP
            elif protocol == 6:
                (source_port, destination_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data) = tcp_segment(data)
                print('    | - TCP Segment:')
                print('        | - Source Port: {}, Destination Port: {}'.format(source_port, destination_port))
                print('        | - Sequence: {}, Acknowledgment: {}'.format(sequence, acknowledgment))
                print('        | - Flags:')
                print('             | - URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN:{}'.format(flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print('        | - Data:')
                print(format_multiline('            | - ', data))

            # UDP
            elif protocol == 17:
                source_port, destination_port, length, data = udp_segment(data)
                print('    | - UDP Segment:')
                print('        | - Source Port: {}, Destination Port: {}, Length: {}'.format(source_port, destination_port, length))

            # Other
            else:
                print('    | - Data:')
                print(format_multiline('        | - ', data))

        else:
            print('| - Data:')
            print(format_multiline('    | - ', data))

        print()
