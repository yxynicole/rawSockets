# A class to represent an IP header

import socket
from struct import *

class IpHeader:

    def __init__(self):
        self.version = 4
        self.ihl = 5
        self.type_of_service = 0
        self.length = 0
        self.identification = 123
        self.frag_offset = 0
        self.ttl = 255
        self.protocol = socket.IPPROTO_TCP
        self.checksum = 0
        self.src_addr = socket.inet_aton('192.168.109.128') # my VM IP address
        self.dest_addr = socket.inet_aton('52.70.229.197') # ccs.neu.edu ip address


    def pack_data(self):
        ihl_version = (self.version << 4) + self.ihl
        ip_header = pack('!BBHHHBBH4s4s', ihl_version, self.type_of_service, self.length, self.identification, self.frag_offset, self.ttl, self.protocol, self.checksum, self.src_addr, self.dest_addr)
        return ip_header