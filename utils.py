from struct import pack, unpack
import ipaddress
from data import *


# Reads Compressed strings in dns message.
def read_dns_string(message, pointer):
    name_string = ''
    while True:
        label_len = message[pointer]
        if label_len > 63:  # Its pointer.
            ptr = unpack('!H', message[pointer:pointer + 2])[0]
            offset = int(format(ptr, '016b')[2:], 2)  # Cut first '11'.
            s, p = read_dns_string(message, offset)
            name_string += s
            pointer += 2  # For 2 bytes of pointer.
            break
        pointer += 1
        if label_len == 0:
            break
        name_string += message[pointer:pointer + label_len].decode() + '.'
        pointer += label_len
    return name_string, pointer


def create_dns_string(string):
    res = b''
    labels = string.split('.')
    for label in labels:
        res += bytes([len(label)])
        res += label.encode()
    return res


class Header:

    q_id = flags = qd_count = an_count = ns_count = ar_count = None

    def __init__(self, info_bytes=None):
        questions_header_bytes = unpack('!6H', info_bytes[:12])
        self.q_id, self.flags, self.qd_count, self.an_count, self.ns_count, self.ar_count = questions_header_bytes
        self.position_in_message = (0, 12)

    def to_bytes(self):
        return pack('!6H', self.q_id, self.flags, self.qd_count, self.an_count,
                    self.ns_count, self.ar_count)


class Question:

    q_name = q_type = q_class = None

    def __init__(self, info_in_bytes=None, pointer=None):
        if info_in_bytes is None:
            return
        start = pointer
        self.q_name, pointer = read_dns_string(info_in_bytes, pointer)
        self.q_type, self.q_class = unpack('!2H', info_in_bytes[pointer:pointer + 4])
        pointer += 4
        self.position_in_message = (start, pointer)

    def to_bytes(self):
        res = b''
        labels = self.q_name.split('.')
        for label in labels:
            res += bytes([len(label)]) + label.encode()
        return res + pack('!2H', self.q_type, self.q_class)

    # Transfers question to string.
    def to_log(self):
        return self.q_name.decode() + '\t' + 'IN' + '\t' + RFC1035_TYPES[self.q_type]


class Answer:

    a_name = a_type = a_class = a_ttl = a_data = None

    def __init__(self, info_in_bytes=None, pointer=None):
        if info_in_bytes is None:
            return
        start = pointer
        self.a_name, pointer = read_dns_string(info_in_bytes, pointer)
        self.a_type, self.a_class = unpack('!2H', info_in_bytes[pointer:pointer + 4])
        pointer += 4
        self.a_ttl = unpack('!I', info_in_bytes[pointer:pointer + 4])[0]
        pointer += 4
        self.a_rdlength = unpack('!H', info_in_bytes[pointer:pointer + 2])[0]
        pointer += 2
        pointer = self.__data_from_bytes(info_in_bytes, pointer)
        self.position_in_message = (start, pointer)

    def __data_from_bytes(self, data_bytes, pointer):
        if RFC1035_TYPES[self.a_type] == 'A':
            ipv4_in_bytes = data_bytes[pointer:pointer + 4]
            pointer += 4
            ip_str = ipaddress.ip_address(ipv4_in_bytes).compressed
            self.a_data = ip_str
        elif RFC1035_TYPES[self.a_type] == 'AAAA':
            ipv6_in_bytes = data_bytes[pointer:pointer + 16]
            pointer += 16
            ip_str = ipaddress.ip_address(ipv6_in_bytes).compressed
            self.a_data = ip_str
        elif RFC1035_TYPES[self.a_type] == 'NS' or RFC1035_TYPES[self.a_type] == 'CNAME':
            name_server_in_bytes, pointer = read_dns_string(data_bytes, pointer)
            self.a_data = name_server_in_bytes
        elif RFC1035_TYPES[self.a_type] == 'SOA':
            primary_name_server, pointer = read_dns_string(data_bytes, pointer)
            host_master, pointer = read_dns_string(data_bytes, pointer)
            serial, refresh, retry, expire, min_ttl = unpack('!5I', data_bytes[pointer:pointer + 20])
            pointer += 20
            self.a_data = primary_name_server + ' ' + host_master + ' ' + str(serial) + ' ' + str(refresh) + ' ' + \
                          str(retry) + ' ' + str(expire) + ' ' + str(min_ttl)
        elif RFC1035_TYPES[self.a_type] == 'MX':
            preference = unpack('!H', data_bytes[pointer:pointer + 2])[0]
            pointer += 2
            if data_bytes[pointer] == 0:
                self.a_data = (str(preference), '')
            else:
                name, pointer = read_dns_string(data_bytes, pointer)
                self.a_data = (str(preference), name)
        elif RFC1035_TYPES[self.a_type] == 'TXT':
            text_length = unpack('!B', data_bytes[pointer:pointer + 1])[0]
            pointer += 1
            text = data_bytes[pointer:pointer + text_length].decode()
            pointer += text_length
            self.a_data = text
        return pointer  # end

    def to_bytes(self):
        res = create_dns_string(self.a_name)
        res += pack('!H', self.a_type)
        res += pack('!H', 0x0001)  # IN
        res += pack('!I', self.a_ttl)
        data_in_bytes = self.__data_to_bytes()
        a_rdlength = len(data_in_bytes)
        res += pack('!H', a_rdlength)
        res += data_in_bytes
        return res

    def __data_to_bytes(self):
        if RFC1035_TYPES[self.a_type] == 'A':
            ipv4_bytes = ipaddress.IPv4Address(self.a_data).packed
            return ipv4_bytes
        elif RFC1035_TYPES[self.a_type] == 'AAAA':
            ipv6_bytes = ipaddress.IPv6Address(self.a_data).packed
            return ipv6_bytes
        elif RFC1035_TYPES[self.a_type] == 'NS' or RFC1035_TYPES[self.a_type] == 'CNAME':
            in_bytes = create_dns_string(self.a_data)
            return in_bytes
        elif RFC1035_TYPES[self.a_type] == 'SOA':
            primary_name_server, host_master, serial, refresh, retry, expire, min_ttl = self.a_data.split()
            prim = create_dns_string(primary_name_server)
            host_m = create_dns_string(host_master)
            in_bytes = prim + host_m + pack('!5I', int(serial), int(refresh), int(retry), int(expire), int(min_ttl))
            return in_bytes
        elif RFC1035_TYPES[self.a_type] == 'MX':
            mx = self.a_data
            in_bytes = pack('!H', int(mx[0]))  # Preference
            mx_server = create_dns_string(mx[1])
            in_bytes += mx_server
            return in_bytes
        elif RFC1035_TYPES[self.a_type] == 'TXT':
            in_bytes = b''
            in_bytes += pack('!B', len(self.a_data))
            in_bytes += self.a_data.encode()
            return in_bytes

    # Transfers answer to string.
    def to_log(self):
        return self.a_name + '\t' + str(self.a_ttl) + '\t' + 'IN' + '\t'\
               + RFC1035_TYPES[self.a_type] + '\t' + self.a_data
