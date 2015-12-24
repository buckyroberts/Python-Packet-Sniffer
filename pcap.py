import struct
import time


class Pcap:

    def __init__(self, filename, link_type=1):
        self.pcap = open(filename, 'wb')
        self.pcap.write(struct.pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def write(self, packet):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(packet)
        self.pcap.write(struct.pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap.write(packet)

    def close(self):
        self.pcap.close()
