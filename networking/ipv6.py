from socket import *
import ipaddress


class IPv6:

    def __init__(self, raw_data, addr):

        self.ipv6_data = raw_data[:40]
        self.version = self.ipv6_data[0] >> 4
        self.trafic_class = self.ipv6_data[0] << 4 | self.ipv6_data[1] >> 4
        self.flow_label = ((self.ipv6_data[1] & 0x00FF) << 16) | (self.ipv6_data[2] << 8) | self.ipv6_data[3]
        self.payload_len = (self.ipv6_data[4]  << 8) | self.ipv6_data[5]
        self.next_header = self.ipv6_data[6]
        self.hop_limit = self.ipv6_data[7]
        self.src = ipaddress.IPv6Address(self.ipv6_data[8:24])
        self.dest = ipaddress.IPv6Address(self.ipv6_data[24:40])
        self.data = raw_data[40:]

    def __str__(self):

        return (
            '\t - IPv6 Packet:\n'
            f'\t\t - Version: {self.version}, Trafic Class: {self.trafic_class},\n'
            f'\t\t - Flow Label : {self.flow_label}, Payload lenght: {self.payload_len},\n'
            f'\t\t - Next Header: {self.next_header}, Hop Limit: {self.hop_limit},\n'
            f'\t\t - Source: {self.src}\n'
            f'\t\t - Destination: {self.dest}\n'
        )