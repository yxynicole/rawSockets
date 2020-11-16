# A class to represent an IP header

import socket
from struct import *

class IpHeader:

    def __init__(self, src_ip, dest_ip):
        self.version = 4
        self.ihl = 5
        self.type_of_service = 0
        self.length = 0
        self.identification = 123
        self.frag_offset = 0
        self.ttl = 255
        self.protocol = socket.IPPROTO_TCP
        self.checksum = 0
        self.src_addr = socket.inet_aton(src_ip) # my VM IP address
        self.dest_addr = socket.inet_aton(dest_ip) # ccs.neu.edu ip address


    def form_ip_header(self):
        ihl_version = (self.version << 4) + self.ihl
        ip_header = pack('!BBHHHBBH4s4s', ihl_version, self.type_of_service, self.length, self.identification, self.frag_offset, self.ttl, self.protocol, self.checksum, self.src_addr, self.dest_addr)
        return ip_header
