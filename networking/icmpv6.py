from networking.icmpv6_messages import ICMPv6Messages

class ICMPv6:

    def __init__(self, raw_data):

        self.messages = ICMPv6Messages()
        self.icmpv6_data = raw_data[:8]
        self.type = self.icmpv6_data[0]
        self.code = self.icmpv6_data[1]
        self.checksum = self.icmpv6_data[2] << 8 | self.icmpv6_data[3]
        self.message_body = self.icmpv6_data[5:8]
        self.data = raw_data[8:]

    def __str__(self):
        result = '\t - ICMPv6 Packet:\n'
        result += f'\t\t - Type: {self.type}, Type Name: {self.messages.icmp6_types[self.type]}\n'
        result += f'\t\t - Code: {self.code}'
        try:
            result += f'\t\t - Code Name: {self.messages.icmp6_codes[self.type][self.code]}\n'
        except:
            result += '\n'
        result += f'\t\t - Checksum: {self.checksum}\n'
        result += f'\t\t - ICMPv6 Data: {self.data}\n'

        return result