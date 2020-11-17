# A class to represent an IP header

import socket
from struct import *

class IPHeader:

    def __init__(self, src_ip, dest_ip):
        self.version = 4
        self.ihl = 5
        self.type_of_service = 0
        self.length = 20
        self.identification = 1
        self.frag_offset = 0
        self.ttl = 255
        self.protocol = socket.IPPROTO_TCP
        self.checksum = 0
        self.src_ip = src_ip # my VM IP address
        self.dest_ip = dest_ip # ccs.neu.edu ip address


    def form_ip_header(self):
        ihl_version = (self.version << 4) + self.ihl
        ip_header = pack('!BBHHHBBH4s4s', ihl_version, self.type_of_service, 
            self.length, self.identification, self.frag_offset, self.ttl, 
            self.protocol, self.checksum, 
            socket.inet_aton(self.src_ip), socket.inet_aton(self.dest_ip))
        return ip_header

    def __str__(self):
        return ("ihl_ver={}, tos={}, len={}, id={}, "
            "frag_offset={}, ttl={}, proto={}, chksum={}, src_ip={}, dest_ip={}"
        ).format((self.version << 4) + self.ihl, self.type_of_service, self.length, 
            self.identification, self.frag_offset, self.ttl, self.protocol, self.checksum,
            self.src_ip, self.dest_ip
        )
