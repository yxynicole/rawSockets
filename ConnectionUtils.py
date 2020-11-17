import socket, sys
from struct import unpack
import binascii
import config

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
        print("-- sent --")
        print(ip_header)
        print(tcp_header)
        print packet[40:]
        # print(' '.join(["{:02x}".format(ord(i)) for i in packet[:20]]))
        # print(' '.join(["{:02x}".format(ord(i)) for i in packet[20:40]]))
        # print(' '.join(["{:02x}".format(ord(i)) for i in packet[40:]]))


def recv(s):
    packet = s.recv(65535)
    ip_header = list(unpack("BBHHHBBH4s4s", packet[0:20]))
    tcp_header = unpack("!HHLLBBHHH", packet[20:40])
    ip_header[8] = socket.inet_ntoa(ip_header[8])
    ip_header[9] = socket.inet_ntoa(ip_header[9])
    if config.DEBUG and tcp_header[1] == config.SRC_PORT:
        print("-- recv --")
        print(ip_header)
        print(tcp_header)
    return ip_header, tcp_header, packet[40:]

# Returns true if source and destination IP address match what is expected
# Still need to add other validations, such as validating checksum
def validate_ip_header(ip_header, expected_source_addr, expected_dest_addr):
    return ip_header[8] == expected_source_addr and ip_header[9] == expected_dest_addr

# Returns the sequence number sent by the server, or -1 if tcp header is invalid
# Still needs to add some more validations, like validating checksum of tcp_header
def validate_syn_ack_tcp_header(tcp_header, sender_port, ack_num):
    # 18 for tcp_header[5] indicates ack and syn flags are set to 1 - a bit hacky can revisist this to make it more clean
    if (tcp_header[1] == sender_port and tcp_header[3] == ack_num and tcp_header[5] == 18):
        return tcp_header[2] #returns sequence number
    else:
        return -1 # returns -1 to indicate not a valid syn_ack response
   
