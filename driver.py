from TCPPacket import *
from IPHeader import *
from ConnectionUtils import *
import binascii, socket, sys
from http import *
from utils import *
from handshake import *
import config
import argparse

parser =  argparse.ArgumentParser('rawhttpget')

parser.add_argument('url')
parser.add_argument('--debug', action='store_true', default=False)


if __name__=='__main__':
    options = parser.parse_args()
    config.DEBUG = options.debug
    hostname, path = extract_hostname_and_path(options.url)
    src_ip = get_sender_IP_address()
    dest_ip = socket.gethostbyname(hostname)
    
    # Send initial syn as part of TCP three-way handshake
    s_ip_header = IPHeader(src_ip, dest_ip)
    s_tcp_header = TCPPacket(src_ip, dest_ip)

    s_sock = create_send_socket()
    r_sock = create_receiver_socket()
    
    do_handshake(s_sock, r_sock, s_ip_header, s_tcp_header, src_ip, dest_ip)
    response = http_get(s_sock, r_sock, hostname, path, src_ip, dest_ip, s_ip_header, s_tcp_header)
    save_file(response, path)

    if config.DEBUG: print("Done")

