from TCPPacket import *
from IPHeader import *
from ConnectionUtils import *
import binascii, socket
from http import *
from utils import *
from handshake import *
import config


if __name__=='__main__':

    url = "http://david.choffnes.com/classes/cs4700fa20/project4.php"
    hostname, path = extract_hostname_and_path(url)
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

    print("end")


