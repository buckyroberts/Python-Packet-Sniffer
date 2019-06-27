from struct import *
import socket

class ipv4:
    def __init__(self, packet):
        iph = packet[:20]
        iph = unpack('!BBHHHBBH4s4s' , iph)

        self.version = iph[0] >> 4
        self.length = (iph[0] & 0xF) * 4
        self.ttl = iph[5]
        self.next_header = iph[6]
        self.src = socket.inet_ntoa(iph[8])
        self.target = socket.inet_ntoa(iph[9])
        self.data = packet[20:]

class ipv6:
    def __init__(self, packet):
        iph = packet[:40]
        iph = unpack('!IHBB16H', iph)

        self.version = iph[0] >> 28 
        self.trafic = (iph[0] >> 20) & 0x00FF
        self.flow_label = iph[0] & 0xFFFF
        self.payload = iph[1]
        self.next_header = iph[2]
        self.hop_limit = iph[3]
        self.src = 'Source: ' +  ipv6_to_string(iph, 4, 12)
        self.target = 'Target: ' +  ipv6_to_string(iph, 12, 20)
        self.data = packet[40:]
def ipv6_to_string(iph, start, end):
    ipv6_string = ''
    for x in range(start, end):
        if iph[x] != 0:
            ipv6_string += str(hex(iph[x]))[2:]
        if x != end-1:
            ipv6_string += ':'

    return ipv6_string

class udp:
    def __init__(self, packet):
        header = unpack("!4H",packet[:8])
        self.src_port = header[0]
        self.dest_port = header[1]
        self.lenght = header[2]
        self.check_sum = header[3]
        self.data = packet[8:]

class tcp:
    def __init__(self, packet):
        tcph = packet[:20]
        tcph = unpack('!2H2I4H', tcph)
   
        self.src_port = tcph[0]
        self.dest_port = tcph[1]
        self.sequence = tcph[2]
        self.acknowledgment = tcph[3]
        self.length = tcph[4] >> 12
        self.reserved = (tcph[4] >> 6) & 0x003F 
        self.flag_urg = (tcph[4] & 0x0020) >> 5 
        self.flag_ack = (tcph[4] & 0x0010) >> 4
        self.flag_psh = (tcph[4] & 0x0008) >> 3
        self.flag_rst = (tcph[4] & 0x0004) >> 2
        self.flag_syn = (tcph[4] & 0x0002) >> 1
        self.flag_fin = (tcph[4] & 0x0001)
        self.window = packet[5]
        self.checkSum = packet[6]
        self.urgPntr = packet[7]

        h_size = self.length * 4
        data_size = len(packet) - h_size
        self.data = packet[h_size:]

class routing:
    def __init__(self, packet):
        header = unpack("!4B", packet[:4])
        self.next_header = header[0]
        self.hdr_ext_len = int(header[1] * 8 + 8)
        self.routing_type = header[2]
        self.seg_left = header[3]
        self.data = packet[self.hdr_ext_len:]

class icmpv6:
    def __init__(self, packet):
        header = unpack("!BBH",packet[:4])
        self.type = header[0]
        self.code = header[1]
        self.checksum = header[2]
        self.data = packet[4:]

class icmp:
    def __init__(self, packet):
        header = unpack("!BBH", packet[:4])
        self.type = header[0]
        self.code = header[1]
        self.checksum = header[2]
        self.data = packet[4:]

class hopbyhop:
    def __init__(self, packet):
        header = unpack("!2B", packet[:2])
        self.next_header = header[0]
        self.hdr_ext_len = int(header[1] * 8 + 8)
        self.data = packet[self.hdr_ext_len:]

class fragment:
    def __init__(self, packet):
        header = unpack("!2BHI", packet[:8])
        self.next_header = header[0]
        self.reserved = header[1]
        self.frag_offset = packet[2] >> 3
        self.m_flag = packet[2] & 1
        self.identification = packet[3]
        self.data = packet[8:]

class destination:
    def __init__(self, packet):
        header = unpack("!2B", packet[:2])
        self.next_header = header[0]
        self.hdr_ext_len = int(header[1] * 8 + 8)
        self.data = packet[self.hdr_ext_len:]
    
class authentication:
    def __init__(self, packet):
        header = unpack("!2BH2I", packet[:12])
        self.next_header = header[0]
        self.payload_len = int(header[1] * 4 + 8)
        self.reserved = header[2]
        self.spi = header[3]
        self.sequence = header[4]
        self.data = packet[self.payload_len:]





