import socket, sys
from struct import unpack
import binascii
import config
from TCPPacket import TCPPacket
from IPHeader import IPHeader

#create a raw socket
def create_send_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error:
        print("Error creating socket")
        sys.exit()
    else:# Tells kernel not to put in headers
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return s

#create a raw socket
def create_receiver_socket():
    try:
        return socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error:
        print("Error creating socket")
        sys.exit()


def get_sender_IP_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("www.google.com", 80))
    return s.getsockname()[0]

   
def send(s, dest_ip, ip_header, tcp_header):
    packet = ip_header.form_ip_header() + tcp_header.form_tcp_packet()
    s.sendto(packet, (dest_ip, 0))
    if config.DEBUG:
        print("\n-- sent --")
        print(ip_header)
        print(tcp_header)


def recv(s):
    packet = s.recv(65535)
    ip_header = IPHeader.from_packet(unpack("BBHHHBBH4s4s", packet[0:20]))
    tcp_header = TCPPacket.from_packet(unpack("!HHLLBBHHH", packet[20:40]), ip_header.src_ip, ip_header.dest_ip)
    tcp_header.data = packet[40:]

    if config.DEBUG and tcp_header.dest_port == config.SRC_PORT:
        print("-- recv --")
        print(ip_header)
        print(tcp_header)
    return ip_header, tcp_header, packet[40:]

# Returns true if source and destination IP address match what is expected
# Still need to add other validations, such as validating checksum
def validate_ip_header(ip_header, expected_source_addr, expected_dest_addr):
    return ip_header.src_ip == expected_source_addr and ip_header.dest_ip == expected_dest_addr

# Returns the sequence number sent by the server, or -1 if tcp header is invalid
def validate_syn_ack_tcp_header(tcp_header, sender_port, ack_num):
    if (tcp_header.dest_port == sender_port and tcp_header.ack_num == ack_num):
        return tcp_header.seq_num #returns sequence number
    else:
        return -1 # returns -1 to indicate not a valid syn_ack response
