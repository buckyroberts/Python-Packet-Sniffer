import socket

from struct import *
from general import *
from networking import *

ETH_HEADER_LEN = 14
IPv4 = '0x800' 
IPv6 = '0x86dd'
ARP = '0x806'

HOP_BY_HOP = 0
DESTINATION_OPTIONS = 60
ROUTING = 43
FRAGMENT = 44
AH = 51
ESP = 50
MOBILITIY = 135
HOST_IDENTITY = 139
SHIM6 = 140

ICMP_IPv6 = 58
UDP = 17
TCP = 6
ICMP_IPv4 = 1
IGMP = 2

TAB_1 = '\t - '
TAB_2 = '\t\t - '
TAB_3 = '\t\t\t - '
TAB_4 = '\t\t\t\t - '

DATA_TAB_1 = '\t   '
DATA_TAB_2 = '\t\t   '
DATA_TAB_3 = '\t\t\t   '
DATA_TAB_4 = '\t\t\t\t   '

def mac_format (mac) :
    formatted_mac = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(mac[0]) , ord(mac[1]) , ord(mac[2]), ord(mac[3]), ord(mac[4]) , ord(mac[5]))
    return formatted_mac


def main():
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3)) 

    while True:
        packet = conn.recvfrom(65535)
        packet = packet[0]

        eth_header = packet[:ETH_HEADER_LEN]
        eth_data = packet[ETH_HEADER_LEN:]
        eth = unpack('!6s6sH' , eth_header)
        eth_protocol = hex(eth[2])
        print '\nEthernet Frame:'
        print TAB_1 + 'Destination: ' + mac_format(eth[0]) + ' Source: ' + mac_format(eth[1]) + ' Protocol: ' + eth_protocol
        
        if eth_protocol == IPv6:
            ipv6_packet = ipv6(eth_data)

            print(TAB_1 + 'IPv6 Packet:')
            print(TAB_2 + 'Version: {}, Trafic Class: {}, Hop Limit: {},'.format(ipv6_packet.version, ipv6_packet.trafic, ipv6_packet.hop_limit))
            print(TAB_2 + 'Next Header: {}, Flow Label: {}, Payload: {}'.format(ipv6_packet.next_header, ipv6_packet.flow_label, ipv6_packet.payload))
            print(TAB_2 + 'Source: {}, Target: {}'.format(ipv6_packet.src, ipv6_packet.target))
            flag = True
            next = ipv6_packet.next_header
            next_packet = ipv6_packet.data

            while flag:             
                if next == TCP:
                    tcp_packet = tcp(next_packet)
                    print(TAB_2 + 'TCP Segment:')
                    print(TAB_3 + 'Source Port: {}, Destination Port: {}'.format(tcp_packet.src_port, tcp_packet.dest_port))
                    print(TAB_3 + 'Sequence: {}, Acknowledgment: {}'.format(tcp_packet.sequence, tcp_packet.acknowledgment))
                    print(TAB_3 + 'Flags:')
                    print(TAB_4 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp_packet.flag_urg, tcp_packet.flag_ack, tcp_packet.flag_psh))
                    print(TAB_4 + 'RST: {}, SYN: {}, FIN: {}'.format(tcp_packet.flag_rst, tcp_packet.flag_syn, tcp_packet.flag_fin))

                    if len(tcp_packet.data) > 0:
                        if tcp_packet.src_port == 80 or tcp_packet.dest_port == 80:
                            print(TAB_3 + 'HTTP Data')
                        else:
                            print(TAB_3 + 'TCP Data')

                    flag = False

                elif next == UDP:
                    udp_packet = udp(next_packet)
                    print(TAB_2 + 'UDP Segment:')
                    print(TAB_3 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp_packet.src_port, udp_packet.dest_port, udp_packet.lenght))

                    flag = False

                elif next == ICMP_IPv6:
                    imcp_packet = icmp(next_packet)
                    print(TAB_2 + 'ICMP Packet:')
                    print(TAB_3 + 'Type: {}, Code: {}, Checksum: {},'.format(imcp_packet.type, imcp_packet.code, imcp_packet.checksum))

                    flag = False

                elif next == HOP_BY_HOP:
                    hbp_packet = hopbyhop(next_packet)
                    print(TAB_2 + 'Hop-by-Hop Segment:')
                    print(TAB_3 + 'Next Header: {}, Header Extention Lenght: {}'.format(hbp_packet.next_header, hbp_packet.hdr_ext_len))
                    next_packet = hbp_packet.data
                    next = hbp_packet.next_header

                elif next == DESTINATION_OPTIONS:
                    destination_packet = destination(next_packet)
                    print(TAB_2 + 'Destination Segment:')
                    print(TAB_3 + 'Next Header: {}, Header Extention Lenght: {}'.format(destination_packet.next_header, destination_packet.hdr_ext_len))
                    next_packet = destination_packet.data
                    next = destination_packet.next_header

                elif next == ROUTING:
                    routing_packet = routing(next_packet)
                    print(TAB_2 + 'Routing Segment:')
                    print(TAB_3 + 'Next Header: {}, Header Extention Lenght: {}'.format(routing_packet.next_header, routing_packet.hdr_ext_len))
                    print(TAB_3 + 'Routing Type: {}, Segments Left: {}'.format(routing_packet.routing_type, routing_packet.seg_left))             
                    next_packet = routing_packet.data
                    next = routing_packet.next_header

                elif next == FRAGMENT:
                    fragment_packet = routing(next_packet)
                    print(TAB_2 + 'Fragment Segment:')
                    print(TAB_3 + 'Next Header: {}, Fragment Offset: {}'.format(fragment_packet.next_header, fragment_packet.frag_offset))
                    print(TAB_3 + 'M Flag: {}, Identification: {}'.format(fragment_packet.m_flag, fragment_packet.identification))             
                    next_packet = fragment_packet.data
                    next = fragment_packet.next_header

                elif next == AH:
                    ah_packet = authentication(next_packet)
                    print(TAB_2 + 'Authentication Segment:')
                    print(TAB_3 + 'Next Header: {}, Payload Lenght: {}'.format(ah_packet.next_header, ah_packet.payload_len))
                    print(TAB_3 + 'Security Parameters Index: {}, Sequence Number: {}'.format(ah_packet.spi, ah_packet.sequence))             
                    next_packet = ah_packet.data
                    next = ah_packet.next_header
                    break

                elif next == ESP:
                    print(TAB_2 + 'ESP Segment')
                    flag = False

                elif next == MOBILITIY:
                    print(TAB_2 + 'Mobility Segment')
                    flag = False

                elif next == HOST_IDENTITY:
                    print(TAB_2 + 'Host Identity Segment')
                    flag = False

                elif next == SHIM6:
                    print(TAB_2 + 'SHIM6 Segment')
                    flag = False

                else:
                    print(TAB_2 + 'Other IPv6 Next Header Type: {}'.format(next))
                    flag = False           

        elif eth_protocol == ARP:
            print(TAB_1 + 'ARP Packet')

        elif eth_protocol == IPv4:
            ipv4_packet = ipv4(eth_data)

            print(TAB_1 + 'IPv4 Packet:')
            print(TAB_2 + 'Version: {}, Header Length: {}, TTL: {},'.format(ipv4_packet.version, ipv4_packet.length, ipv4_packet.ttl))
            print(TAB_2 + 'Next Header: {}, Source: {}, Target: {}'.format(ipv4_packet.next_header, ipv4_packet.src, ipv4_packet.target))

            if ipv4_packet.next_header == ICMP_IPv4:
                icmp_header = icmp(ipv4_packet.data)
                print(TAB_1 + 'ICMP Packet:')
                print(TAB_2 + 'Type: {}, Code: {}, Checksum: {},'.format(icmp_header.type, icmp_header.code, icmp_header.checksum))

            elif ipv4_packet.next_header == IGMP:
                print(TAB_2 + 'IGMP Segment')

            elif ipv4_packet.next_header == TCP:         
                tcp_header = tcp(ipv4_packet.data)
                print(TAB_2 + 'TCP Segment:')
                print(TAB_3 + 'Source Port: {}, Destination Port: {}'.format(tcp_header.src_port, tcp_header.dest_port))
                print(TAB_3 + 'Sequence: {}, Acknowledgment: {}'.format(tcp_header.sequence, tcp_header.acknowledgment))
                print(TAB_3 + 'Flags:')
                print(TAB_4 + 'URG: {}, ACK: {}, PSH: {}'.format(tcp_header.flag_urg, tcp_header.flag_ack, tcp_header.flag_psh))
                print(TAB_4 + 'RST: {}, SYN: {}, FIN: {}'.format(tcp_header.flag_rst, tcp_header.flag_syn, tcp_header.flag_fin))

                if len(tcp_header.data) > 0:
                    if tcp_header.src_port == 80 or tcp_header.dest_port == 80:
                        print(TAB_3 + 'HTTP Data')
                    else:
                        print(TAB_3 + 'TCP Data')

            elif ipv4_packet.next_header == UDP: 
                udp_header = udp(ipv4_packet.data)
                print(TAB_2 + 'UDP Segment:')
                print(TAB_3 + 'Source Port: {}, Destination Port: {}, Length: {}'.format(udp_header.src_port, udp_header.dest_port, udp_header.lenght))

            else:
                print('Other IPv4 protocol {}'.format(ipv4_packet.next_header))
                
main()
