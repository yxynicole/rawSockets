import socket
from struct import *
import binascii

def get_sender_IP_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("www.google.com", 80))
    return s.getsockname()[0]

def create_send_socket():
     
    #create a raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    except socket.error:
        print("Error creating socket")
        sys.exit()
    
    return s

def create_receiver_socket():
    
    #create a raw socket
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error:
        print("Error creating socket")
        sys.exit()

    return s



# Returns true if source and destination IP address match what is expected
# Still need to add other validations, such as validating checksum
def validate_ip_header(full_packet, expected_source_addr, expected_dest_addr):
    ip_header = unpack("BBHHHBBH4s4s", full_packet[0:20]) #IP header should be the first 20 bytes of the full packet
    return (socket.inet_ntoa(ip_header[8]) == expected_source_addr and socket.inet_ntoa(ip_header[9]) == expected_dest_addr)

# Returns the sequence number sent by the server, or -1 if tcp header is invalid
# Still needs to add some more validations, like validating checksum of tcp_header
def validate_syn_ack_tcp_header(full_packet, sender_port, ack_num):
    tcp_header = unpack("!HHLLBBHHH", full_packet[20:40])

    # 18 for tcp_header[5] indicates ack and syn flags are set to 1 - a bit hacky can revisist this to make it more clean
    if (tcp_header[1] == sender_port and tcp_header[3] == ack_num and tcp_header[5] == 18):
        return tcp_header[2] #returns sequence number
    else:
        return -1 # returns -1 to indicate not a valid syn_ack response
   
