# Class to represent a TCP header

import socket
from struct import *

class TcpHeader:

    def __init__(self):
        self.src_port = 1234
        self.dest_port = 80
        self.seq_num = 500
        self.ack_num = 3
        self.data_offset = 5
        self.fin_flag = 0
        self.syn_flag = 1
        self.rst_flag = 0
        self.psh_flag = 0
        self.ack_flag = 0
        self.urg_flag = 0
        self.window = socket.htons(5840)
        self.checksum = 0 
        self.urgent_pointer = 0

    def pack_data(self):
        offset_res = (self.data_offset << 4) + 0
        flags = self.fin_flag + (self.syn_flag << 1) + (self.rst_flag << 2) + (self.psh_flag << 3) + (self.ack_flag << 4) + (self.urg_flag << 5)
        tcp_header = pack('!HHLLBBHHH' , self.src_port, self.dest_port, self.seq_num, self.ack_num, offset_res, flags,  self.window, self.checksum, self.urgent_pointer)
        return tcp_header