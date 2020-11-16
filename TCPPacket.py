import socket
from struct import *
import sys

class TCPPacket:

    def __init__(self, sender_port, seq_num, ack_num, src_ip, dest_ip, syn_flag, ack_flag, data):
        self.src_port = sender_port
        self.dest_port = 80
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.data_offset = 5 << 4
        self.window = socket.htons(5840)
        self.checksum = 0 
        self.urgent_pointer = 0
        self.data = data
        self.set_flags(syn_flag, ack_flag)

        self.src_ip = src_ip
        self.dest_ip = dest_ip

    def set_flags(self, syn_flag, ack_flag):
        fin_flag = 0
        syn_flag = syn_flag
        rst_flag = 0
        psh_flag = 0
        ack_flag = ack_flag
        urg_flag = 0

        self.flags = fin_flag + (syn_flag << 1) + (rst_flag << 2) + (psh_flag << 3) + (ack_flag << 4) + (urg_flag << 5)
    
    def calculate_checksum(self, body):
        b_sum = 0

        for i in range(0, len(body), 2):

            int1 = ord(body[i])
            int2 = ord(body[i+1])
            b_sum = b_sum + (int1+(int2 << 8))
            
        # One's Complement
        b_sum = b_sum+ (b_sum >> 16)
        b_sum = ~b_sum & 0xffff
        return b_sum

    def set_checksum(self):

        temp_header = pack('!HHLLBBHHH', 
            self.src_port, 
            self.dest_port, 
            self.seq_num,
            self.ack_num,
            self.data_offset,
            self.flags,
            self.window,
            self.checksum,
            self.urgent_pointer
        )

        # pseudo header fields
        src_address = socket.inet_aton(self.src_ip)
        dest_address = socket.inet_aton(self.dest_ip)
        placeholder = 0
        protocol = socket.IPPROTO_TCP
        tcp_length = len(temp_header) + len(self.data)
        print("tcp_length is " + str(tcp_length))

        psh = pack('!4s4sBBH', src_address, dest_address, placeholder, protocol, tcp_length)

        body = psh + temp_header + self.data

        self.checksum = self.calculate_checksum(body)
        return
    
    def form_tcp_packet(self):
        self.set_checksum()
        tcp_header = tcp_header = pack('!HHLLBBH', 
            self.src_port, 
            self.dest_port, 
            self.seq_num, 
            self.ack_num,
            self.data_offset,
            self.flags,
            self.window) + pack('H', self.checksum) + pack('!H', self.urgent_pointer)
        tcp_packet = tcp_header + self.data
        return tcp_packet
   
